export const CLASSIFICATIONS=['public','internal','confidential','restricted'] as const;
export type Classification=typeof CLASSIFICATIONS[number];
export const ACCOUNTS=['enterprise','personal','unknown'] as const;
export type AccountKind=typeof ACCOUNTS[number];
export type ControlDecision='allow'|'redact'|'review'|'block';
export interface DestinationRule {
  readonly id:string;readonly origin:string;readonly accounts:readonly AccountKind[];
  readonly requireVerifiedAccount:boolean;readonly requireManagedDevice:boolean;readonly requireProvenance:boolean;
  readonly maxClassification:Classification;readonly groups:readonly string[];
}
export interface EnterprisePolicy {
  readonly schemaVersion:1;readonly tenantId:string;readonly policyId:string;readonly revision:number;
  readonly notBefore:number;readonly expiresAt:number;readonly destinations:readonly DestinationRule[];
  readonly unknownDestination:'block'|'review';readonly piiAction:'redact'|'block';
  readonly injectionAction:'review'|'block';readonly blockActiveContent:boolean;readonly maxInputBytes:number;
}
/** MUST be constructed by AIDR's authenticated enforcement point, not request JSON, model output,
 * DOM account labels, HTTP X-Tenant headers or caller-supplied assertions. */
export interface TrustedContext {
  readonly tenantId:string;readonly subjectId:string;readonly sessionId:string;
  readonly groups:readonly string[];readonly scopes:readonly string[];
  readonly device:'managed'|'unmanaged'|'unknown';
  readonly account:AccountKind;readonly accountVerified:boolean;
  readonly destination:string;readonly channel:'browser'|'api'|'retrieval'|'tool'|'output';
  readonly assetIds:readonly string[];
}
export function maximumClassification(...labels:Classification[]):Classification {
  return CLASSIFICATIONS[Math.max(0,...labels.map(x=>CLASSIFICATIONS.indexOf(x)))]!;
}
