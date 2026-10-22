export type IconName = 'shield' | 'search' | 'alert' | 'layers' | 'chain' | 'arrow' | 'evidence' | 'refresh' | 'clock' | 'grid' | 'file' | 'check';
const paths: Record<IconName, string> = {
  shield: 'M12 3 4 6v6c0 5 8 9 8 9s8-4 8-9V6l-8-3Zm-3 9 2 2 4-5',
  search: 'M21 21l-5-5M18 10a8 8 0 1 1-16 0 8 8 0 0 1 16 0',
  alert: 'M12 8v5m0 4h.01M10 3 2 18a2 2 0 0 0 2 3h16a2 2 0 0 0 2-3L14 3a2 2 0 0 0-4 0',
  layers: 'm12 3 10 5-10 5L2 8l10-5ZM2 12l10 5 10-5M2 16l10 5 10-5',
  chain: 'M8 8 5 5m14 14-3-3M8 16l8-8M7 3a4 4 0 1 1-4 4 4 4 0 0 1 4-4Zm10 10a4 4 0 1 1-4 4 4 4 0 0 1 4-4Z',
  arrow: 'M4 12h16m-6-6 6 6-6 6',
  evidence: 'M14 2H5a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V9l-7-7Zm0 0v7h7M7 13h10M7 17h6',
  refresh: 'M20 7v5h-5M4 17v-5h5M6 6a8 8 0 0 1 13 2M5 16a8 8 0 0 0 13 2',
  clock: 'M12 7v5l3 2M22 12a10 10 0 1 1-20 0 10 10 0 0 1 20 0',
  grid: 'M3 3h7v7H3V3Zm11 0h7v7h-7V3ZM3 14h7v7H3v-7Zm11 0h7v7h-7v-7Z',
  file: 'M14 2H5v20h14V7l-5-5Zm0 0v5h5M8 12h8M8 16h8',
  check: 'm5 12 4 4L19 6',
};
export function Icon({name, className = ''}: {name: IconName; className?: string}) {
  return <svg className={'ui-icon '+className} width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d={paths[name]}/></svg>;
}
