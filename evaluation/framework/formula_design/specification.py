"""Versioned mathematical specification written before experimental execution."""
from . import OUT
from .runtime import save


V4 = r'''# V4_SCORE_FORMULA_SPEC

Execution baseline: `alert-correlation-v5-preformula-candidate-v1`.
Formula identity: `frozen-v4-role-context`. Threshold is 0.65 (unrounded).
The v0 seven signed contributions are an audit layer, NOT the v4 score.

For available dimensions D_f (AVAILABLE_MATCH or AVAILABLE_MISMATCH), let d_i
be configured dimension weight and s_i be strength. UNAVAILABLE and
NOT_APPLICABLE are excluded, while observed mismatches have strength zero:

    a_f = 1[D_f is nonempty]
    u_f = sum(d_i s_i)/sum(d_i), i in D_f, for f != relation
    u_relation = max(s_i), i in D_relation; empty family strength = 0
    w = {time:.20, entity:.30, relation:.36, behavior:.04, source:.10}
    A = sum(a_f w_f)
    M = sum(a_f w_f u_f)
    W = sum(w_f) = 1
    Q = M/A if A>0 else 0
    mass = M/W
    positive_v4 = .65 Q + .35 mass = (.65/A + .35/W) M
    raw_v4 = positive_v4 - .45 C - .40 D
    score_v4 = min(1, max(0, raw_v4))

No additional bonuses or score rescaling exist. Family contribution is
(.65/A + .35/W) w_f u_f. The fixed W affects mass even if a family cannot be
observed. Quality DOES already exclude unavailable families; it is inaccurate
to claim the entire v4 denominator is fixed. A zero but observable family still
enters A. Conditional ceiling if only available families could reach strength 1:
.65 + .35 A/W, before penalties and actual strength ceilings.

Time: T = exp(-ln(2) |delta_seconds| / h). h is the configured chronological
category transition half-life (300 seconds fallback; overrides stay frozen).
No label, alert ID or detector description chooses a transition.

Entity dimension weights: IP .25, HOST .55, ACCOUNT .70, SESSION .90,
PROCESS .80, URL .85, DOMAIN .35, FILE .90, COMMAND .90.
Freeze N and df per dedupe group. Let P=max(N,100):

    r(e) = max(.10, ln((P+1)/(df(e)+1))/ln(P+1))
    reliability_v4(e) = (.10 + .90 r(e)) role_factor descriptor_factor

Same role factor 1; src/dst bridge .8; other role .5. Destination-only IP gets
an additional .25. A process description gets .25, never an instance claim.
Non-specific URL/FILE/COMMAND gets another .25; concrete scoped resources
retain 1. For each entity type select maximal reliability, lexical identity tie.
Already consumed attested relation/flow entities are suppressed from additive
entity evidence. No shared entity gives observed zero if both types exist;
one-sided missing gives UNAVAILABLE; neither side or consumed type gives NA.
The original EntityScore noisy-OR 1-product(1-x(e)) remains a seven-item audit
value and does NOT replace these v4 dimensions.

Metadata family: .20 times the maximum of category compatibility, same-source
rule equality and same-source signature equality. Cross-source vendor strings
are NA; unknown categories are unavailable; alert_type is excluded in v4.
This family is supporting metadata, never causal progression evidence.

Relation family: max(attested configured relation strength, verified network
continuity). Frozen five attested types retain their existing field gates.
Network requires non-self network endpoints on both alerts, strict timestamp
order, scoped earlier dst/later src equality, complete distinct flow identities
with equal protocol when event pointers are configured, port context or mapped
transition >=.7, AND known different categories with compatibility >=.7 in v4.
Network strength=.90 times max(.10+.90r) over bridging entities. Consumed
relation endpoints are not independently credited as network evidence.

Source family: unknown or same origin earns zero. Only confirmed-independent,
context-bridged complementary facets earn the configured source score; sensor
or product-name difference is insufficient. There is no independent-source bonus
outside this family.

C=max(configured applicable soft conflict strengths, default 0). Different
target sets without a context bridge: .8; no context .5; beyond behavior window
.6; reversed explicit relation 1; proven incompatible session 1. Existing scoped
isolation/session hard guards independently reject. Valid confirmed network flow
can remove the different-target soft penalty. v4 compares target sets, including
HOST versus ENDPOINT representations, without proving they are exclusive assets.
This can apply .45*.8=.36 even when representation equivalence is unknown.

Unmerged duplicate similarity is the frozen duplicate scorer (rule/payload/
target/time plus observation identity). D=clamp((dup-.50)/.50,0,1).
Observation equivalence (or fewer than two observation identities when event
pointers configured) separately fails the evidence gate; two wrappers are not
two independent facts. No duplicate score or dedupe membership changes here.

V4 evidence gate requires at least one primary fact, mass>=.25, and no duplicate
observation risk. Entity primary needs reliability>=.6 and non-hot status;
HOST/ACCOUNT additionally require different same-source rule/signature OR
different known categories; PROCESS needs a real instance; SESSION needs
declared scopes and rarity>=.5; URL/FILE/COMMAND need specificity and rarity>=.5.
Generic IP/DOMAIN are never primary. Attested relations are primary. Verified
non-hot network strength>=.6 can be primary. Time and metadata cannot be primary.
Gate does not alter numeric score, so a positive score may still be rejected.

Formal undirected admission: no hard conflict, actual non-time evidence,
evidence gate passes, and unrounded score>=.65. Group score is the greatest
VALID complete member score over G1xG2, not maximum components across members.
Ties use source timestamp, target timestamp, source ID, target ID. This research
compares every completed MEMBER score, discloses reference gate outcomes, and
does not publish CorrelationEdges, merge Incidents or reconstruct chains.
'''


V5 = r'''# Experimental formula definitions (predeclared)

Each dimension returns state, strength s, reliability rho, provenance. SUPPORT
has s>0; OBSERVED_ZERO has s=0 and participates in available denominator;
UNAVAILABLE/NA/AMBIGUOUS do not. Missing/unknown are never contradictions.
Reliability is an interpretable design hypothesis, not fitted probability.

F0: exactly the frozen V4 formula in V4_SCORE_FORMULA_SPEC.md.

F1 (weighted additive): Q_v4 - redesigned conflicts - unchanged duplicate,
clamped to [0,1]. It removes the fixed mass term, retaining original dimensions,
family weights, metadata cap, time and old gate. A weak-only score is capped at
.45. No role-strength correction is used. This cap is necessary to prevent
available-only normalization turning an isolated weak match into certainty.

F2 (weighted additive semantic evidence): let A be observable non-time
dimensions, retaining observed zero. Weight k_i=d_i*rho_i. Then

    U = sum(k_i s_i)/sum(k_i), denominator zero => U=0
    Tcompat = .80 + .20 T
    raw_F2 = U Tcompat - redesigned conflict - .40 D

Generic reliability by type: IP .15, HOST .35, ACCOUNT .30, SESSION/PROCESS .80,
URL/FILE/COMMAND .60, DOMAIN .10. Descriptor factors remain in strength.
Role-bound same canonical execution host .70; compatible explicit account
subject roles .75; monitored IP/endpoint continuity .55; verified relation/flow
.95; metadata .20; confirmed complementary source .60. These values are one
predeclared non-fitted hypothesis, also compared with equal reliability.
Matching entity identity uses existing scope; no asset aliases are invented.
Compatible account roles are authenticated_account, target_account,
source_account, audit_account. Generic account alone does not get that bonus.
Role-continuity strength preserves rarity and removes only v4's generic .5
other-role reduction. It never claims source-to-target causal propagation.

F3 (bounded interactions and confidence): same U and Tcompat as F2. Define
independent semantic mass L as sum(max(rho_i s_i) per semantic type). HOST
and monitored-IP evidence share one asset slot, so they do not count twice.
Time/metadata/source cannot create coverage. Coverage c=min(1,L/.8).

    H=max(role-host strengths), A=max(role-account strengths)
    R=max(role-continuity strengths), S=confirmed source complement strength
    I=min(.20, c(.15 H A + .05 R T + .05 S R))
    raw_F3 = U c Tcompat + I - redesigned conflict - .40 D

All absent maxima are zero. Direct/flow entities consumed by V4 stay consumed;
the interaction is a bounded joint-context reward, not an extra observation.

Conflict taxonomy: HARD_CONTRADICTION keeps verified isolation/exclusivity
guards and penalty .45*strength. SOFT_INCONSISTENCY (e.g. behavior-window
incompatibility) costs .08*strength. UNKNOWN_EQUIVALENCE (different same-kind
targets without exclusivity proof) and REPRESENTATION_DIFFERENCE (disjoint
HOST/ENDPOINT kinds) cost zero and remain visible as uncertainty. Aggregate
penalty is maximum, not sum. Different port/host alone proves neither attack
incompatibility nor same-role, same-context asset exclusion. The current v1
canonical schema has no endpoint exclusivity proof; this research does not
extract one from arbitrary raw keys. Synthetic proof tests use a typed seam
requiring explicit same-role/scope/context/moment and bound references.

Safety: scores clamp to [0,1]; without attested relation, host+account joint
context, or strong session/instance identity, score<=.45. No actual non-time
semantic evidence, hard guard, or duplicate-only observation => score 0.
This ceiling applies before reference admission in all F1-F3.

F1 retains the old gate. F2/F3 compare three alternative reference gates: hard
requires strong joint/attested context; soft multiplies weak-context score by .5;
hybrid requires a role/flow/direct context and applies the weak ceiling. All
retain the absolute time-only exclusion and hard guards. Default comparison
uses hybrid. No gate changes production or creates a direction.

Predeclared ablations on F3: remove time (compatibility=1 and remove role*time
term), remove role-aware entity (generic reliability and original strengths),
remove conflict redesign (V4 C), remove coverage (c=1), remove interactions
(I=0). Equal-reliability sensitivity sets rho_i=1 without fitting. Missing-
family counterfactuals remove unavailable dimensions or set them to observed
zero; synthetic rich/sparse tests hold real semantic support constant.

Selection: semantic safety tests and all integrity/leakage checks must pass;
strict descriptive P(GT>explicit-negative) must exceed F0; all four tails
(explicit max, hard-touch max, background p99/max) must be <=F0+.05; average GT
lift must exceed average explicit-negative lift. Select simplest among passing
F1/F2/F3. No threshold, weights or parameters are searched after label loading.
If no model passes, SELECTED=false and gate BLOCKED. Six development GT edges
cannot justify population performance or calibrated probabilities.
'''


def write():
    OUT.mkdir(parents=True,exist_ok=True)
    (OUT/'V4_SCORE_FORMULA_SPEC.md').write_text(V4,encoding='utf8')
    (OUT/'V5_FORMULA_CANDIDATES.md').write_text(V5,encoding='utf8')
    save(OUT/'v4_formula_spec.json',dict(identity='frozen-v4-role-context',
         expression='clamp(0.65*M/A+0.35*M/W-0.45*C-0.40*D,0,1)',
         specification='V4_SCORE_FORMULA_SPEC.md',bonuses=[],threshold=.65))
    save(OUT/'formula_candidates.json',dict(F0='frozen-v4-role-context',
         F1='clamp(Q_v4-Cnew-0.40*D,0,1), weak ceiling and evidence gate',
         F2='clamp(U*(0.80+0.20*T)-Cnew-0.40*D,0,1), weak ceiling and hybrid gate',
         F3='clamp(U*c*(0.80+0.20*T)+I-Cnew-0.40*D,0,1), weak ceiling and hybrid gate',
         specification='V5_FORMULA_CANDIDATES.md',machine_learning=False,optimization=False,threshold_calibration=False))


if __name__=='__main__':write()
