import {defineConfig} from '@playwright/test';
export default defineConfig({testDir:'./e2e',testMatch:['home-ui.spec.ts','stage-runs.spec.ts','overview.spec.ts','modules.spec.ts','stage-workbench.spec.ts'],timeout:180000,expect:{timeout:30000},workers:1,
  reporter:[['list'],['junit',{outputFile:'../outputs/home_ui_checks/browser.xml'}]],outputDir:'../outputs/home_ui_checks/browser-artifacts',
  use:{baseURL:process.env.TRACEBACK_WEB_URL||'http://127.0.0.1:8765',viewport:{width:1440,height:900},screenshot:'only-on-failure',trace:'retain-on-failure',launchOptions:process.env.TRACEBACK_BROWSER_EXECUTABLE?{executablePath:process.env.TRACEBACK_BROWSER_EXECUTABLE}:{}}});
