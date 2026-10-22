import type {Stage, StageRelation} from '../types/stageAnalysis';

export const FLOW_NODE_WIDTH=220, FLOW_NODE_HEIGHT=80;

// Normalize the display strength: formal ⑨ kinds (DIRECTED_EDGE/UNDIRECTED_EDGE)
// carry the same resolved/unresolved direction semantics as the legacy strong
// kinds; display_kind is the renderer-facing strength, relation_type stays the
// authoritative source value.
const displayKind = (r: StageRelation) => r.display_kind ?? r.relation_type;

// Remove only redundant display edges of the same strength and evidence kind.
// Every omitted edge must still have a path through retained, real relations.
export function flowRelations(relations: StageRelation[], stages: Stage[] = []) {
  const kept=[...relations].sort((a,b)=>a.relation_id.localeCompare(b.relation_id));
  const order=new Map([...stages].sort((a,b)=>a.start_time.localeCompare(b.start_time) || a.stage_id.localeCompare(b.stage_id)).map((s,i)=>[s.stage_id,i]));
  const span=(r: StageRelation)=>Math.abs((order.get(r.stage_a_id) ?? 0)-(order.get(r.stage_b_id) ?? 0));
  for(const edge of [...kept].sort((a,b)=>span(b)-span(a))) {
    const undirected=displayKind(edge)==='STRONG_UNDIRECTED';
    const start=undirected?edge.stage_a_id:edge.from_stage_id, end=undirected?edge.stage_b_id:edge.to_stage_id;
    if(!start || !end || start===end) continue;
    const visited=new Set([start]), pending=[start];
    while(pending.length) {
      const id=pending.pop()!;
      for(const other of kept) {
        if(other===edge || displayKind(other)!==displayKind(edge) || other.evidence_type!==edge.evidence_type) continue;
        const target=undirected?(other.stage_a_id===id?other.stage_b_id:other.stage_b_id===id?other.stage_a_id:null):other.from_stage_id===id?other.to_stage_id:null;
        if(!target || visited.has(target)) continue;
        visited.add(target);pending.push(target);
      }
    }
    if(visited.has(end)) kept.splice(kept.indexOf(edge),1);
  }
  return kept;
}

export function layoutStageFlow(stages: Stage[], relations: StageRelation[]) {
  const ordered=[...stages].sort((a,b)=>a.start_time.localeCompare(b.start_time) || a.stage_id.localeCompare(b.stage_id));
  const ids=new Set(ordered.map(s=>s.stage_id));
  const directed=relations.filter(r=>displayKind(r)!=='STRONG_UNDIRECTED' && r.from_stage_id && r.to_stage_id && ids.has(r.from_stage_id) && ids.has(r.to_stage_id));
  const reachable=new Map<string,Set<string>>();
  for(const id of ids) {
    const visited=new Set([id]), pending=[id];
    while(pending.length) {
      const current=pending.pop()!;
      for(const r of directed) if(r.from_stage_id===current && !visited.has(r.to_stage_id!)) {visited.add(r.to_stage_id!);pending.push(r.to_stage_id!);}
    }
    reachable.set(id,visited);
  }
  // Mutually reachable stages share a layer; retain cycle edges in the drawing.
  const components: string[][]=[], membership=new Map<string,number>();
  for(const id of ids) {
    if(membership.has(id)) continue;
    const group=[...ids].filter(other=>!membership.has(other) && reachable.get(id)!.has(other) && reachable.get(other)!.has(id));
    group.forEach(member=>membership.set(member,components.length));components.push(group);
  }
  const ranks=components.map(()=>0);
  for(let pass=0;pass<components.length;pass++) {
    let changed=false;
    for(const r of directed) {
      const a=membership.get(r.from_stage_id!)!, b=membership.get(r.to_stage_id!)!;
      if(a!==b && ranks[b]<ranks[a]+1) {ranks[b]=ranks[a]+1;changed=true;}
    }
    if(!changed) break;
  }
  const layers: Stage[][]=Array.from({length:Math.max(0,...ranks)+1},()=>[]);
  ordered.forEach(s=>layers[ranks[membership.get(s.stage_id)!]].push(s));
  // Alternate predecessor/successor barycentres to align branches and joins.
  for(let pass=0;pass<6;pass++) {
    const sequence=pass%2?[...layers].reverse():layers;
    for(const layer of sequence) {
      const position=new Map(layers.flatMap(row=>row.map((s,i)=>[s.stage_id,(i+.5)/row.length] as const)));
      const barycentre=(id: string)=>{
        const neighbors=directed.filter(r=>pass%2?r.from_stage_id===id:r.to_stage_id===id).map(r=>position.get((pass%2?r.to_stage_id:r.from_stage_id)!)!);
        return neighbors.length?neighbors.reduce((a,b)=>a+b,0)/neighbors.length:position.get(id)!;
      };
      layer.sort((a,b)=>barycentre(a.stage_id)-barycentre(b.stage_id));
    }
  }
  const columns=Math.min(3,Math.max(1,...layers.map(row=>row.length)));
  const width=Math.max(760,columns*280+160);
  let top=80;
  const nodes=layers.flatMap((row,rank)=>{
    const result=row.map((stage,i)=>{
      const subrow=Math.floor(i/3), count=Math.min(3,row.length-subrow*3);
      return {stage,rank,x:(width-count*280+60)/2+(i%3)*280,y:top+subrow*148,index:ordered.indexOf(stage)+1};
    });
    top+=Math.max(1,Math.ceil(row.length/3))*148;
    return result;
  });
  const height=Math.max(300,top+40);
  return {nodes,width,height,layerCount:layers.length,hasCycle:components.some(group=>group.length>1) || directed.some(r=>r.from_stage_id===r.to_stage_id)};
}
