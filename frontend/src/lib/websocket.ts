'use client';

import { useEffect, useRef, useState, useCallback } from 'react';
import { upsertAlertInPGlite, recordTriageInPGlite } from './pglite';
import { AlertRecord } from '@/types/alert';

export type SocketStatus = 'connected' | 'connecting' | 'disconnected';

export function useAlertWebSocket(onAlertChange?: () => void) {
  const [status, setStatus] = useState<SocketStatus>('disconnected');
  const [lastMessage, setLastMessage] = useState<any>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null);

  const connect = useCallback(() => {
    if (typeof window === 'undefined') return;

    const wsUrl =
      process.env.NEXT_PUBLIC_WS_URL ||
      `ws://${window.location.hostname}:8080/ws/alerts`;

    setStatus('connecting');

    try {
      const socket = new WebSocket(wsUrl);
      wsRef.current = socket;

      socket.onopen = () => {
        setStatus('connected');
        console.log('[SOC WebSocket] Connected to SOAR Backend Core at', wsUrl);
      };

      socket.onmessage = async (event) => {
        try {
          const data = JSON.parse(event.data);
          setLastMessage(data);

          if (data.event === 'alert_enriched' && data.alert) {
            const incomingAlert: AlertRecord = data.alert;
            await upsertAlertInPGlite(incomingAlert);
            if (onAlertChange) onAlertChange();
          } else if (data.event === 'alert_triaged') {
            await recordTriageInPGlite(
              data.alert_uuid,
              data.actor || 'Remote Telegram Callback',
              data.action,
              data.status,
              data.notes
            );
            if (onAlertChange) onAlertChange();
          }
        } catch (err) {
          console.error('[SOC WebSocket] Error handling message:', err);
        }
      };

      socket.onclose = () => {
        setStatus('disconnected');
        // Auto-reconnect after 3 seconds
        if (reconnectTimeoutRef.current) clearTimeout(reconnectTimeoutRef.current);
        reconnectTimeoutRef.current = setTimeout(() => {
          connect();
        }, 3000);
      };

      socket.onerror = (err) => {
        console.warn('[SOC WebSocket] Connection issue:', err);
        socket.close();
      };
    } catch (e) {
      console.error('[SOC WebSocket] Init failed:', e);
      setStatus('disconnected');
    }
  }, [onAlertChange]);

  useEffect(() => {
    connect();

    return () => {
      if (reconnectTimeoutRef.current) clearTimeout(reconnectTimeoutRef.current);
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, [connect]);

  return { status, lastMessage };
}
