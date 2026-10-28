'use client';

import React, { useEffect, useState } from 'react';
import { PlaybookExecution, PlaybookStep } from '@/types/alert';
import {
  CheckCircle2,
  Clock,
  Loader2,
  ShieldCheck,
  Ban,
  Activity,
  AlertOctagon,
  X,
  Server,
  Lock,
  Send,
} from 'lucide-react';

interface PlaybookDrawerProps {
  execution: PlaybookExecution | null;
  onClose: () => void;
}

export const PlaybookDrawer: React.FC<PlaybookDrawerProps> = ({ execution, onClose }) => {
  const [currentExec, setCurrentExec] = useState<PlaybookExecution | null>(execution);

  useEffect(() => {
    if (!execution) {
      setCurrentExec(null);
      return;
    }

    setCurrentExec(execution);

    // Simulate animated step-by-step SOAR execution
    let stepIndex = 0;
    const interval = setInterval(() => {
      setCurrentExec((prev) => {
        if (!prev) return null;
        const updatedSteps = [...prev.steps];
        if (stepIndex < updatedSteps.length) {
          updatedSteps[stepIndex] = {
            ...updatedSteps[stepIndex],
            status: 'completed',
          };
          stepIndex++;
          if (stepIndex < updatedSteps.length) {
            updatedSteps[stepIndex] = {
              ...updatedSteps[stepIndex],
              status: 'running',
            };
          }
        }

        const isDone = stepIndex >= updatedSteps.length;
        if (isDone) {
          clearInterval(interval);
        }

        return {
          ...prev,
          steps: updatedSteps,
          status: isDone ? 'success' : 'running',
          completedAt: isDone ? new Date().toISOString() : undefined,
        };
      });
    }, 650);

    return () => clearInterval(interval);
  }, [execution]);

  if (!currentExec) return null;

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/50 dark:bg-black/70 backdrop-blur-xs animate-in fade-in">
      <div className="bg-white dark:bg-zinc-950 border-l border-zinc-200 dark:border-zinc-800 w-full max-w-xl h-full flex flex-col shadow-2xl animate-in slide-in-from-right duration-200 overflow-hidden">
        {/* Top Header */}
        <div className="px-6 py-4 border-b border-zinc-200 dark:border-zinc-800 flex items-center justify-between bg-zinc-50 dark:bg-zinc-900/60 shrink-0">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-purple-100 text-purple-600 dark:bg-purple-950/80 dark:text-purple-400 rounded-xl">
              <Activity className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-[10px] font-mono uppercase font-bold tracking-wider px-2 py-0.5 rounded bg-purple-100 text-purple-800 dark:bg-purple-950 dark:text-purple-300 border border-purple-200 dark:border-purple-800">
                  SOAR Playbook Engine
                </span>
                <span
                  className={`text-[10px] uppercase font-bold px-2 py-0.5 rounded-full ${
                    currentExec.status === 'success'
                      ? 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300'
                      : 'bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300 animate-pulse'
                  }`}
                >
                  {currentExec.status === 'success' ? 'Execution Completed' : 'Running Automation...'}
                </span>
              </div>
              <h3 className="text-sm sm:text-base font-bold text-zinc-900 dark:text-white mt-1">
                {currentExec.name}
              </h3>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-zinc-500 hover:text-zinc-900 dark:text-zinc-400 dark:hover:text-white hover:bg-zinc-100 dark:hover:bg-zinc-800 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-5 text-xs">
          {/* Metadata Card */}
          <div className="p-3 bg-zinc-50 dark:bg-zinc-900/60 border border-zinc-200 dark:border-zinc-800 rounded-xl grid grid-cols-2 gap-3 text-[11px]">
            <div>
              <span className="text-zinc-400">Trigger Action:</span>
              <div className="font-semibold text-zinc-800 dark:text-zinc-200 uppercase font-mono">
                {currentExec.triggerAction}
              </div>
            </div>
            <div>
              <span className="text-zinc-400">Target Alert:</span>
              <div className="font-semibold text-blue-600 dark:text-blue-400 font-mono">
                {currentExec.alertUUID}
              </div>
            </div>
            <div>
              <span className="text-zinc-400">Execution Started:</span>
              <div className="text-zinc-700 dark:text-zinc-300 font-mono">
                {new Date(currentExec.startedAt).toLocaleTimeString()}
              </div>
            </div>
            <div>
              <span className="text-zinc-400">Completed At:</span>
              <div className="text-zinc-700 dark:text-zinc-300 font-mono">
                {currentExec.completedAt ? new Date(currentExec.completedAt).toLocaleTimeString() : 'In Progress...'}
              </div>
            </div>
          </div>

          {/* Stepper Pipeline */}
          <div>
            <h4 className="text-[11px] font-bold uppercase tracking-wider text-zinc-500 dark:text-zinc-400 mb-3">
              Automated Containment Pipeline ({currentExec.steps.length} Steps)
            </h4>

            <div className="space-y-3 relative before:content-[''] before:absolute before:left-3.5 before:top-3 before:bottom-3 before:w-0.5 before:bg-zinc-200 dark:before:bg-zinc-800">
              {currentExec.steps.map((step, idx) => (
                <div key={step.id} className="relative pl-8">
                  {/* Step Status Icon */}
                  <span
                    className={`absolute left-1.5 top-2 -translate-x-1/2 w-5 h-5 rounded-full flex items-center justify-center text-[10px] font-bold shadow-2xs ${
                      step.status === 'completed'
                        ? 'bg-emerald-500 text-white'
                        : step.status === 'running'
                        ? 'bg-blue-600 text-white animate-spin'
                        : 'bg-zinc-200 dark:bg-zinc-800 text-zinc-500'
                    }`}
                  >
                    {step.status === 'completed' ? (
                      <CheckCircle2 className="w-3.5 h-3.5" />
                    ) : step.status === 'running' ? (
                      <Loader2 className="w-3 h-3" />
                    ) : (
                      idx + 1
                    )}
                  </span>

                  {/* Step Card */}
                  <div
                    className={`p-3 rounded-xl border transition ${
                      step.status === 'running'
                        ? 'bg-blue-50/70 border-blue-400 dark:bg-blue-950/40 dark:border-blue-600 shadow-sm'
                        : step.status === 'completed'
                        ? 'bg-white dark:bg-zinc-900 border-zinc-200 dark:border-zinc-800 shadow-2xs'
                        : 'bg-zinc-50/50 dark:bg-zinc-950/40 border-zinc-200/60 dark:border-zinc-800/60 opacity-60'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <div className="font-semibold text-zinc-800 dark:text-zinc-200 text-xs">
                        {step.title}
                      </div>
                      <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-zinc-100 dark:bg-zinc-800 text-zinc-600 dark:text-zinc-400">
                        {step.target}
                      </span>
                    </div>

                    {step.output && (
                      <div className="mt-2 p-2 bg-zinc-900 text-emerald-400 rounded font-mono text-[10px] shadow-inner">
                        &gt; {step.output}
                      </div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Success Banner */}
          {currentExec.status === 'success' && (
            <div className="p-3 bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-300 dark:border-emerald-800 text-emerald-800 dark:text-emerald-200 rounded-xl text-xs flex items-center justify-between shadow-2xs">
              <div className="flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-emerald-600 shrink-0" />
                <span>All multi-vendor containment playbooks executed and verified.</span>
              </div>
              <button
                onClick={onClose}
                className="px-2.5 py-1 bg-emerald-600 text-white rounded font-medium hover:bg-emerald-500 transition text-[11px]"
              >
                Done
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
