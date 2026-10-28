import {useEffect, useState} from 'react';

const SECTIONS = [
  {id: 'incident-overview', label: '概况'},
  {id: 'attack-chain', label: '攻击链'},
  {id: 'incident-evidence', label: '证据'},
  {id: 'incident-timeline', label: '时间线'},
  {id: 'ai-report', label: 'AI 研判'},
] as const;

/** Sticky in-page navigation for the long incident detail page. */
export function DetailNav() {
  const [active, setActive] = useState<string>(SECTIONS[0].id);
  useEffect(() => {
    if (!('IntersectionObserver' in window)) return;
    const elements = SECTIONS.map(section => document.getElementById(section.id)).filter((element): element is HTMLElement => Boolean(element));
    const observer = new IntersectionObserver(entries => {
      const visible = entries.filter(entry => entry.isIntersecting).sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top)[0];
      if (visible) setActive(visible.target.id);
    }, {rootMargin: '-20% 0px -60% 0px', threshold: [0, 1]});
    elements.forEach(element => observer.observe(element));
    return () => observer.disconnect();
  }, []);
  return <nav aria-label="页内导航" className="detail-toc">{SECTIONS.map(section => <a aria-current={active === section.id ? 'location' : undefined} href={'#' + section.id} key={section.id}>{section.label}</a>)}</nav>;
}
