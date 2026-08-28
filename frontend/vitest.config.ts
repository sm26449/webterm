import { defineConfig } from 'vitest/config'

// Config SEPARAT de vite.config.ts, deliberat: build-ul de imagine (vite build) nu
// trebuie să depindă de vitest. Mediul e 'node' — testele unitare de lib stubuiesc
// singure window/localStorage, fără jsdom (o dependență mare pentru două globale).
export default defineConfig({
  test: {
    environment: 'node',
    include: ['src/**/*.test.ts'],
  },
})
