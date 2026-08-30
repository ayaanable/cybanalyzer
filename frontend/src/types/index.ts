export type Node = {id:string;name:string;type:string;kind:string;criticality:number;description?:string;properties:Record<string,unknown>};
export type Edge = {id:string;source:string;target:string;type:string;difficulty:number;description:string;properties:Record<string,unknown>};
export type Vuln = {id:string;asset_id:string;name:string;severity:number;exploitability:number;mitre_technique?:string};
export type Environment = {id:string;name:string;nodes:Node[];relationships:Edge[];vulnerabilities:Vuln[]};
export type AttackPath = {id:string;node_ids:string[];relationship_ids:string[];steps:number;risk_score:number;severity:string;entry_point:string;target:string;techniques:string[];explanation:string};
