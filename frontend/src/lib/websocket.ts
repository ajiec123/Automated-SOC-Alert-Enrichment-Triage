'use client';

import { useEffect, useRef, useState } from 'react';
import { upsertAlertInPGlite, recordTriageInPGlite } from './pglite';
import { AlertRecord } from '@/types/alert';

export type SocketStatus = 'connected' | 'connecting' | 'disconnected';

// Exponential backoff parameters
const INITIAL_BACKOFF_MS = 2000;
const MAX_BACKOFF_MS = 30000;
const MAX_RETRIES = 10;

export function useAlertWebSocket(onAlertChange?: () => void) {
  const [status, setStatus] = useState<SocketStatus>('disconnected');
  const [lastMessage, setLastMessage] = useState<any>(null);

  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const retryCountRef = useRef<number>(0);
  const isUnmountedRef = useRef<boolean>(false);
  const onAlertChangeRef = useRef(onAlertChange);

  // Keep latest onAlertChange in ref so changing dependencies does not trigger reconnection loops
  useEffect(() => {
    onAlertChangeRef.current = onAlertChange;
  }, [onAlertChange]);

  useEffect(() => {
    isUnmountedRef.current = false;

    function connect() {
      if (typeof window === 'undefined' || isUnmountedRef.current) return;

      // If already connected or actively connecting, avoid duplicate connection attempts
      if (
        wsRef.current &&
        (wsRef.current.readyState === WebSocket.OPEN ||
          wsRef.current.readyState === WebSocket.CONNECTING)
      ) {
        return;
      }

      const wsUrl =
        process.env.NEXT_PUBLIC_WS_URL ||
        `ws://${window.location.hostname}:8080/ws/alerts`;

      setStatus('connecting');

      try {
        const socket = new WebSocket(wsUrl);
        wsRef.current = socket;

        socket.onopen = () => {
          if (isUnmountedRef.current) {
            socket.close();
            return;
          }
          setStatus('connected');
          retryCountRef.current = 0; // Reset backoff on successful handshake
          console.log('[SOC WebSocket] Connected to SOAR Backend Core at', wsUrl);
        };

        socket.onmessage = async (event) => {
          if (isUnmountedRef.current) return;
          try {
            const data = JSON.parse(event.data);
            setLastMessage(data);

            if (data.event === 'alert_enriched' && data.alert) {
              const incomingAlert: AlertRecord = data.alert;
              await upsertAlertInPGlite(incomingAlert);
              if (onAlertChangeRef.current) onAlertChangeRef.current();
            } else if (data.event === 'alert_triaged') {
              await recordTriageInPGlite(
                data.alert_uuid,
                data.actor || 'Remote Telegram Callback',
                data.action,
                data.status,
                data.notes,
                data.hypothesis_selected
              );
              if (onAlertChangeRef.current) onAlertChangeRef.current();
            }
          } catch (err) {
            console.error('[SOC WebSocket] Error handling message:', err);
          }
        };

        socket.onclose = (event) => {
          if (isUnmountedRef.current) return;
          setStatus('disconnected');

          // If maximum retry limit reached, stop spamming the server
          if (retryCountRef.current >= MAX_RETRIES) {
            console.warn(
              `[SOC WebSocket] Max reconnect attempts (${MAX_RETRIES}) reached. Polling paused to prevent server exhaustion. Use manual refresh or reload.`
            );
            return;
          }

          // Exponential backoff with jitter: backoff = min(initial * 2^retries, max) + jitter
          const baseDelay = Math.min(
            INITIAL_BACKOFF_MS * Math.pow(1.8, retryCountRef.current),
            MAX_BACKOFF_MS
          );
          const jitter = Math.floor(Math.random() * 1000);
          const backoffDelay = Math.round(baseDelay + jitter);

          retryCountRef.current += 1;

          console.log(
            `[SOC WebSocket] Connection closed (code: ${event.code}). Next reconnection attempt #${retryCountRef.current} in ${(
              backoffDelay / 1000
            ).toFixed(1)}s...`
          );

          if (reconnectTimeoutRef.current) {
            clearTimeout(reconnectTimeoutRef.current);
          }

          reconnectTimeoutRef.current = setTimeout(() => {
            if (!isUnmountedRef.current) {
              connect();
            }
          }, backoffDelay);
        };

        socket.onerror = () => {
          // Socket error will trigger onclose; avoid duplicate manual close calls
        };
      } catch (e) {
        setStatus('disconnected');
        console.error('[SOC WebSocket] Init failed:', e);
      }
    }

    connect();

    return () => {
      isUnmountedRef.current = true;
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, []); // Run effect once on mount, keep callbacks fresh with ref

  return { status, lastMessage };
}
