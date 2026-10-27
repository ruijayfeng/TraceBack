import '@testing-library/jest-dom/vitest';
import {cleanup} from '@testing-library/react';
import {afterEach, beforeEach, vi} from 'vitest';
import {api} from '../api/client';
// Existing page fixtures predate imported runs; each test can override this
// empty history when exercising the upload/task panel.
beforeEach(()=>{vi.spyOn(api,'stageRuns').mockResolvedValue({items:[]});});
afterEach(() => {cleanup();vi.restoreAllMocks();vi.unstubAllGlobals();});
Element.prototype.scrollIntoView = () => {};
window.scrollTo = () => {};
