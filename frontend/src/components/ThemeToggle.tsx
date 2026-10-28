'use client';

import React from 'react';
import { useTheme } from '@/lib/theme';
import { Sun, Moon } from 'lucide-react';

export const ThemeToggle: React.FC = () => {
  const { theme, toggleTheme } = useTheme();

  return (
    <button
      onClick={toggleTheme}
      type="button"
      className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border text-xs font-medium transition shadow-sm
        bg-white text-zinc-700 border-zinc-200 hover:bg-zinc-100 hover:text-zinc-900
        dark:bg-zinc-800 dark:text-zinc-200 dark:border-zinc-700 dark:hover:bg-zinc-700 dark:hover:text-white"
      title={`Switch to ${theme === 'dark' ? 'Light' : 'Dark'} Mode`}
      aria-label="Toggle theme"
    >
      {theme === 'dark' ? (
        <>
          <Sun className="w-3.5 h-3.5 text-amber-400" />
          <span className="hidden sm:inline">Light</span>
        </>
      ) : (
        <>
          <Moon className="w-3.5 h-3.5 text-blue-600" />
          <span className="hidden sm:inline">Dark</span>
        </>
      )}
    </button>
  );
};
