import {useEffect, useState} from 'react';

const SECTIONS = [
  {id: 'incident-overview', label: '概况'},
  {id: 'attack-chain', label: '攻击链'},
  {id: 'incident-evidence', label: '证据'},
  {id: 'incident-timeline', label: '时间线'},
  {id: 'ai-report', label: 'AI 研判'},
] as const;

/** Sticky in-page navigation for the long incident detail page (underline tabs). */
export function DetailNav() {
  const [active, setActive] = useState<string>(SECTIONS[0].id);
  useEffect(() => {
    const offset = 48 + 80;
    let frame = 0;
    const sync = () => {
      frame = 0;
      let current: string = SECTIONS[0].id;
      for (const section of SECTIONS) {
        const element = document.getElementById(section.id);
        if (element && element.getBoundingClientRect().top <= offset) current = section.id;
      }
      setActive(current);
    };
    const onScroll = () => {if (!frame) frame = requestAnimationFrame(sync);};
    sync();
    addEventListener('scroll', onScroll, {passive: true});
    addEventListener('resize', onScroll);
    return () => {removeEventListener('scroll', onScroll);removeEventListener('resize', onScroll);cancelAnimationFrame(frame);};
  }, []);
  return <nav aria-label="页内导航" className="detail-toc">{SECTIONS.map(section => <a aria-current={active === section.id ? 'location' : undefined} href={'#' + section.id} key={section.id}>{section.label}</a>)}</nav>;
}
