import {render,screen} from '@testing-library/react';
import {describe,it,expect} from 'vitest';
import {AiStatus} from '../components/ui/ai-status';

describe('rare-ui ai-status (T83 follow-up)', () => {
  it('renders a labelled, reduced-motion-safe generating status', () => {
    render(<AiStatus elapsed={3} label="正在生成…" state="thinking" />);
    expect(screen.getByText('正在生成…')).toBeInTheDocument();
    expect(document.querySelector('[data-slot="ai-status"]')).toHaveAttribute('data-state','thinking');
    expect(screen.getByText('3s')).toBeInTheDocument();
  });
});
