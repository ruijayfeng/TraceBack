import {defineConfig} from '@playwright/test';
export default defineConfig({testDir:'./e2e',timeout:180000,expect:{timeout:30000},workers:1,fullyParallel:false,
  reporter:[['list'],['junit',{outputFile:'../outputs/task08/browser.xml'}]],
  outputDir:'../outputs/task08/browser-artifacts',
  use:{baseURL:process.env.TRACEBACK_WEB_URL || 'http://127.0.0.1:8000',viewport:{width:1440,height:1050},screenshot:'only-on-failure',trace:'retain-on-failure',launchOptions:process.env.TRACEBACK_BROWSER_EXECUTABLE ? {executablePath:process.env.TRACEBACK_BROWSER_EXECUTABLE} : {}},
});
