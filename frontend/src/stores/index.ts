// src/stores/index.ts
import { create } from 'zustand';
import { devtools, persist } from 'zustand/middleware';

interface Settings {
  theme: 'light' | 'dark' | 'system';
  language: string;
  sidebarCollapsed: boolean;
  autoRefresh: boolean;
  refreshInterval: number;
}

interface GlobalState {
  settings: Settings;
  updateSettings: (settings: Partial<Settings>) => void;
  resetSettings: () => void;
}

const initialSettings: Settings = {
  theme: 'system',
  language: 'en',
  sidebarCollapsed: false,
  autoRefresh: true,
  refreshInterval: 30000
};

export const useStore = create<GlobalState>()(
  devtools(
    persist(
      (set) => ({
        settings: initialSettings,
        updateSettings: (newSettings) =>
          set((state) => ({
            settings: { ...state.settings, ...newSettings }
          })),
        resetSettings: () =>
          set(() => ({
            settings: initialSettings
          }))
      }),
      {
        name: 'irssh-settings'
      }
    )
  )
);
