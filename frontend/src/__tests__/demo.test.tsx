import {render,screen} from '@testing-library/react';
import {it,expect,vi} from 'vitest';
import App from '../App';

it.each([
  [0,'network_unavailable'],[404,'analysis_not_found'],[409,'snapshot_integrity_error'],
])('final Demo renders unavailable backend/snapshot (%s) without infinite loading',async(status,code)=>{
  history.replaceState({},'', '/?analysis_id=ana_'+'0'.repeat(64));
  vi.stubGlobal('fetch',vi.fn().mockImplementation(async()=>{
    if(status===0) throw new TypeError('connection refused');
    return new Response(JSON.stringify({detail:code}),{status,headers:{'Content-Type':'application/json'}});
  }));
  render(<App/>);
  const messages=await screen.findAllByRole('alert');
  expect(messages.some(m=>m.textContent?.includes(code))).toBe(true);
  expect(screen.queryByText('正在读取安全事件列表…')).not.toBeInTheDocument();
});
