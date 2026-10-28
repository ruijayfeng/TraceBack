import {render,screen,fireEvent} from '@testing-library/react';
import {describe,it,expect,vi} from 'vitest';
import App from '../App';
import {ErrorState} from '../components/ui/error-state';
import {describeError} from '../lib/errors';

describe('error matrix', () => {
  it('keeps the raw code and only offers retry for retryable errors', () => {
    const retry=vi.fn();
    const {rerender}=render(<ErrorState error="network_unavailable" onRetry={retry} scope="测试"/>);
    expect(screen.getByRole('alert')).toHaveTextContent('network_unavailable');
    fireEvent.click(screen.getByRole('button',{name:/重试/}));
    expect(retry).toHaveBeenCalled();
    rerender(<ErrorState error="analysis_not_found" onRetry={retry} scope="测试"/>);
    expect(screen.getByRole('alert')).toHaveTextContent('analysis_not_found');
    expect(screen.queryByRole('button',{name:/重试/})).not.toBeInTheDocument();
  });
  it('maps known, invalid-filter and unknown codes to stable messages', () => {
    expect(describeError('analysis_not_found').title).toContain('未找到');
    expect(describeError('invalid_filter:severity').title).toContain('筛选');
    expect(describeError('future_code').code).toBe('future_code');
    expect(describeError('').code).toBe('request_failed');
  });
});

describe('global shell', () => {
  it('opens the keyboard help with ? and closes it with Escape', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('offline')));
    history.replaceState({},'','/');
    render(<App/>);
    fireEvent.keyDown(document,{key:'?'});
    expect(await screen.findByRole('dialog',{name:'键盘快捷键'})).toBeInTheDocument();
    expect(screen.getByText('在事件列表行之间上下移动焦点')).toBeInTheDocument();
    fireEvent.keyDown(document,{key:'Escape'});
    expect(await screen.findByRole('heading',{name:/从碎片告警/})).toBeInTheDocument();
  });
  it('shows an offline banner and removes it when connectivity returns', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('offline')));
    const onLine=Object.getOwnPropertyDescriptor(window.navigator,'onLine');
    Object.defineProperty(window.navigator,'onLine',{configurable:true,value:false});
    history.replaceState({},'','/');
    render(<App/>);
    fireEvent(window,new Event('offline'));
    expect(await screen.findByText(/当前处于离线状态/)).toBeInTheDocument();
    Object.defineProperty(window.navigator,'onLine',{configurable:true,value:true});
    fireEvent(window,new Event('online'));
    expect(screen.queryByText(/当前处于离线状态/)).not.toBeInTheDocument();
    if (onLine) Object.defineProperty(window.navigator,'onLine',onLine);
  });
});
