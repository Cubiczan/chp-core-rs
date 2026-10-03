/-
  Core.lean — Lean 4 (core library only) formal model of the chp-core-rs
  ledger / consensus / gate core. Compile with:

      ~/.elan/bin/lean Core.lean

  No `sorry` / `admit` / custom axioms. The hash function is an abstract
  parameter `H` throughout: every chain property proved here is structural
  and holds for *any* `H`. The single place where a hash property is needed
  (tamper detection) takes it as an explicit hypothesis
  (`H` assigns a different value to the tampered fields), which is the
  formal shadow of SHA-256 collision resistance.

  What is modelled (see NOTES.md for the line-level mapping):
    * `DecisionLedger` (src/ledger.rs) — hash-chained entry list:
      `create` (genesis), `append`, `verify`, `repair`.
    * `replay` grading (src/consensus.rs) — unanimous / disputed /
      insufficient over the recorded round entries of one decision.
    * `apply_third_party_validation` (src/validators.rs) — the
      PROVISIONAL_LOCK → LOCKED / → EXPLORING transition.
    * `evaluate_r0_gate` (src/gates.rs) — verdict = PASS iff all 4 checks PASS.
    * `foundation_floor` (src/foundation.rs) — 70 / 85 / 100 domain floors.

  Deliberate abstractions:
    * Rust `phase : u8`, `round : u32` are modelled as `Nat`; no arithmetic
      is performed on them anywhere in the modelled code paths.
    * An entry's JSON object is split into `fields` (exactly the values the
      Rust `entry_hash` reads, ledger.rs:138-152) and the stored
      `entryHash`, which the Rust hash never reads.
    * Rust `verify` additionally *mutates* flag fields
      (`envelope_valid`/`integrity_valid`); those fields are not part of the
      hash and never influence the returned index list, so the model's
      `verify` is the pure index computation of ledger.rs:245-271.
-/

namespace ChpCore

/-! ## Entries and sealing (ledger.rs) -/

/-- The fields of a ledger entry that the chain hash is computed over —
    exactly the values interpolated into the format string at
    ledger.rs:147-150, plus `prevHash`. -/
structure Fields where
  ts : String
  decisionId : String
  phase : Nat
  round : Nat
  entryType : String
  body : String
  envelope : String
  prevHash : String
deriving DecidableEq, Repr

/-- A ledger entry: its hashed fields plus the stored chain hash
    (`entry_hash` in the JSON object). -/
structure Entry where
  fields : Fields
  entryHash : String
deriving DecidableEq, Repr

/-- `DecisionLedger::seal` (ledger.rs:154-158) composed with the
    `prev_hash` assignment at the call sites: set `prevHash := p`, then
    store `H (pos+1) fields`, where `pos` is the entry's 0-based index
    (ledger.rs:149 formats `index + 1`). -/
def sealAt (H : Nat → Fields → String) (pos : Nat) (e : Entry) (p : String) : Entry :=
  let f : Fields := { e.fields with prevHash := p }
  { fields := f, entryHash := H (pos + 1) f }

@[simp] theorem sealAt_prevHash (H : Nat → Fields → String) (pos : Nat) (e : Entry) (p : String) :
    (sealAt H pos e p).fields.prevHash = p := rfl

@[simp] theorem sealAt_entryHash (H : Nat → Fields → String) (pos : Nat) (e : Entry) (p : String) :
    (sealAt H pos e p).entryHash = H (pos + 1) (sealAt H pos e p).fields := rfl

/-- The stored hash of the last entry of `l`, threading the genesis
    predecessor `p` (ledger.rs uses `entries[index-1].entry_hash`, and
    `GENESIS_HASH = ""` before index 0). -/
def lastHashFrom (p : String) : List Entry → String
  | [] => p
  | e :: t => lastHashFrom e.entryHash t

/-- Chain well-formedness: the invariant `create`/`append` maintain and
    `repair` restores. At each position `n` (0-based) the entry's
    `prevHash` is the previous entry's stored hash (`""` for the genesis
    entry, `GENESIS_HASH`, ledger.rs:36) and its stored `entryHash` is the
    seal of its fields at that position. -/
inductive Chain (H : Nat → Fields → String) : Nat → String → List Entry → Prop where
  | nil : Chain H n p []
  | cons (hprev : e.fields.prevHash = p) (hhash : e.entryHash = H (n + 1) e.fields)
      (rest : Chain H (n + 1) e.entryHash l) : Chain H n p (e :: l)

/-- A freshly sealed singleton is a chain. Used for `create` and for the
    singleton tail in `append`. -/
theorem chain_singleton (H : Nat → Fields → String) (pos : Nat) (e : Entry) (p : String) :
    Chain H pos p [sealAt H pos e p] :=
  Chain.cons rfl rfl Chain.nil

/-! ## create / append (ledger.rs:161-235) -/

/-- `DecisionLedger::create` as an operation on ledger states. The Rust
    function (ledger.rs:161-190):
      * returns `Err` — state untouched — when the ledger *file* exists
        (modelled by `fileExists = true` yielding `none`);
      * otherwise **clears the in-memory entries** (ledger.rs:186) and
        installs a single genesis entry sealed at index 0 with
        `prev_hash = GENESIS_HASH = ""`.
    Note the result does not depend on the previous in-memory entries at
    all; see NOTES.md for why that matters. -/
def createOp (H : Nat → Fields → String) (fileExists : Bool) (e : Entry) :
    Option (List Entry) :=
  if fileExists then none else some [sealAt H 0 e ""]

theorem createOp_file_exists (H : Nat → Fields → String) (e : Entry) :
    createOp H true e = none := rfl

theorem createOp_fresh (H : Nat → Fields → String) (e : Entry) :
    createOp H false e = some [sealAt H 0 e ""] := rfl

/-- A created ledger is a well-formed chain of length 1. -/
theorem createOp_chain (H : Nat → Fields → String) (e : Entry) :
    Chain H 0 "" [sealAt H 0 e ""] :=
  chain_singleton H 0 e ""

/-- The genesis entry's `prevHash` is the genesis constant `""`. -/
theorem createOp_genesis_prev (H : Nat → Fields → String) (e : Entry) :
    (sealAt H 0 e "").fields.prevHash = "" := rfl

/-- `DecisionLedger::append` (ledger.rs:194-235) on a non-empty ledger:
    the new entry is sealed at position `l.length` with predecessor the
    last entry's *stored* hash, and concatenated. (Envelope construction
    for `oracle_post` entries happens before sealing and is part of
    `fields`; it does not affect the chain shape.) -/
def appendEntry (H : Nat → Fields → String) (l : List Entry) (e : Entry) : List Entry :=
  l ++ [sealAt H l.length e (lastHashFrom "" l)]

/-- `DecisionLedger::append` with its failure case: appending to an
    empty ledger (no genesis) is an error (ledger.rs:203-207) and the
    state is unchanged — modelled by `none`. -/
def appendOp (H : Nat → Fields → String) (l : List Entry) (e : Entry) :
    Option (List Entry) :=
  if l = [] then none else some (appendEntry H l e)

theorem appendOp_empty (H : Nat → Fields → String) (e : Entry) :
    appendOp H [] e = none := rfl

/-- **History is never rewritten by append**: the old ledger is a prefix
    of the new one. -/
theorem appendEntry_prefix (H : Nat → Fields → String) (l : List Entry) (e : Entry) :
    l <+: appendEntry H l e :=
  ⟨[sealAt H l.length e (lastHashFrom "" l)], rfl⟩

theorem appendEntry_length (H : Nat → Fields → String) (l : List Entry) (e : Entry) :
    (appendEntry H l e).length = l.length + 1 := by
  simp [appendEntry]

/-- Chain decomposition over `++`: a chain over `a ++ b` splits into a
    chain over `a` and a chain over `b` starting at the threaded
    position/predecessor that `a` ends with. -/
theorem chain_append_inv (H : Nat → Fields → String) :
    ∀ {n p a b}, Chain H n p (a ++ b) →
      Chain H n p a ∧ Chain H (n + a.length) (lastHashFrom p a) b := by
  intro n p a
  induction a generalizing n p with
  | nil => intro b h; exact ⟨Chain.nil, h⟩
  | cons x t ih =>
      intro b h
      cases h with
      | cons hprev hhash rest =>
          obtain ⟨h1, h2⟩ := ih rest
          refine ⟨Chain.cons hprev hhash h1, ?_⟩
          have hlen : n + (x :: t).length = n + 1 + t.length := by simp; omega
          rw [hlen]
          exact h2

/-- Chain composition over `++` (converse direction). -/
theorem chain_append (H : Nat → Fields → String) :
    ∀ {n p a b}, Chain H n p a →
      Chain H (n + a.length) (lastHashFrom p a) b → Chain H n p (a ++ b) := by
  intro n p a
  induction a generalizing n p with
  | nil => intro b _ h2; exact h2
  | cons x t ih =>
      intro b h1 h2
      cases h1 with
      | cons hprev hhash rest =>
          refine Chain.cons hprev hhash (ih rest ?_)
          have hlen : n + (x :: t).length = n + 1 + t.length := by simp; omega
          rw [hlen] at h2
          exact h2

/-- **Append preserves the chain invariant**: appending to a well-formed
    ledger yields a well-formed ledger. -/
theorem appendEntry_chain (H : Nat → Fields → String) {l : List Entry} (e : Entry)
    (h : Chain H 0 "" l) : Chain H 0 "" (appendEntry H l e) := by
  unfold appendEntry
  refine chain_append (H := H) h ?_
  rw [Nat.zero_add]
  exact chain_singleton H l.length e (lastHashFrom "" l)

/-! ## verify (ledger.rs:245-271) -/

/-- `DecisionLedger::verify`, the pure index computation: walk the
    ledger threading the position `n` and the previous entry's *stored*
    hash `p`; flag position `n+1` (1-based, as returned) when the stored
    hash differs from the recomputed seal **or** the entry's `prevHash`
    differs from the previous stored hash. Crucially the walk always
    continues with the *stored* hash (ledger.rs:262-269), so one tampered
    entry does not shift the indexes of later entries. -/
def verifyFrom (H : Nat → Fields → String) (n : Nat) (p : String) :
    List Entry → List Nat
  | [] => []
  | e :: t =>
      (if H (n + 1) e.fields ≠ e.entryHash ∨ e.fields.prevHash ≠ p then [n + 1] else [])
        ++ verifyFrom H (n + 1) e.entryHash t

def verify (H : Nat → Fields → String) (l : List Entry) : List Nat :=
  verifyFrom H 0 "" l

/-- **A well-formed chain verifies clean.** -/
theorem verifyFrom_of_chain (H : Nat → Fields → String) :
    ∀ {n p l}, Chain H n p l → verifyFrom H n p l = [] := by
  intro n p l h
  induction l generalizing n p with
  | nil => rfl
  | cons e t ih =>
      cases h with
      | cons hprev hhash rest =>
          simp only [verifyFrom]
          have hnot : ¬ (H (n + 1) e.fields ≠ e.entryHash ∨ e.fields.prevHash ≠ p) := by
            intro hc
            cases hc with
            | inl hne => exact hne hhash.symm
            | inr hne => exact hne hprev
          rw [if_neg hnot, List.nil_append]
          exact ih rest

/-- **Verification is complete**: if `verify` flags nothing, the ledger
    really is a well-formed chain (the two checks in `verify` are exactly
    the two chain conditions). -/
theorem chain_of_verifyFrom_eq_nil (H : Nat → Fields → String) :
    ∀ {n p l}, verifyFrom H n p l = [] → Chain H n p l := by
  intro n p l
  induction l generalizing n p with
  | nil => intro _; exact Chain.nil
  | cons e t ih =>
      intro h
      simp only [verifyFrom] at h
      obtain ⟨hstep, hrest⟩ := List.append_eq_nil_iff.mp h
      have hcond : ¬ (H (n + 1) e.fields ≠ e.entryHash ∨ e.fields.prevHash ≠ p) := by
        intro hc
        rw [if_pos hc] at hstep
        exact absurd hstep (List.cons_ne_nil _ _)
      have hhash : e.entryHash = H (n + 1) e.fields := by
        by_cases h : e.entryHash = H (n + 1) e.fields
        · exact h
        · exfalso; exact hcond (Or.inl (Ne.symm h))
      have hprev : e.fields.prevHash = p := by
        by_cases h : e.fields.prevHash = p
        · exact h
        · exfalso; exact hcond (Or.inr h)
      exact Chain.cons hprev hhash (ih hrest)

theorem verify_eq_nil_iff_chain (H : Nat → Fields → String) (l : List Entry) :
    verify H l = [] ↔ Chain H 0 "" l :=
  ⟨fun h => chain_of_verifyFrom_eq_nil H h, fun h => verifyFrom_of_chain H h⟩

/-- Decomposition of `verify` over `++` — the walk over `a ++ b` is the
    walk over `a` followed by the walk over `b` at the threaded
    position/predecessor. -/
theorem verifyFrom_append (H : Nat → Fields → String) :
    ∀ {n p} (a b : List Entry),
      verifyFrom H n p (a ++ b) =
        verifyFrom H n p a ++ verifyFrom H (n + a.length) (lastHashFrom p a) b := by
  intro n p a
  induction a generalizing n p with
  | nil => intro b; rfl
  | cons e t ih =>
      intro b
      simp only [List.cons_append, verifyFrom, List.length_cons, lastHashFrom]
      rw [ih (n := n + 1) (p := e.entryHash) b]
      have hlen : n + 1 + t.length = n + (t.length + 1) := by omega
      rw [hlen, List.append_assoc]

/-- **Tamper evidence.** Take a well-formed chain `l₁ ++ [e] ++ l₂` and
    change only the *body* of `e` (hash fields untouched — the on-disk
    tamper of ledger.rs's `body_tamper_detected_but_index_preserved`
    test). Provided the hash actually separates the tampered fields
    (`H … e' ≠ H … e` — the collision-resistance hypothesis), `verify`
    flags exactly position `l₁.length + 1`. -/
theorem verify_flags_body_tamper (H : Nat → Fields → String)
    {l₁ l₂ : List Entry} {e : Entry} {b' : String}
    (hchain : Chain H 0 "" (l₁ ++ [e] ++ l₂))
    (hH : H (l₁.length + 1) { e.fields with body := b' } ≠ e.entryHash) :
    (l₁.length + 1) ∈ verify H (l₁ ++ [{ e with fields := { e.fields with body := b' } }] ++ l₂) := by
  -- The ledger splits as `(l₁ ++ [e]) ++ l₂`; split the chain twice.
  obtain ⟨hA, -⟩ := chain_append_inv H hchain
  obtain ⟨hpre, -⟩ := chain_append_inv H hA
  have hpre_nil : verifyFrom H 0 "" l₁ = [] := verifyFrom_of_chain H hpre
  rw [verify, verifyFrom_append, verifyFrom_append, hpre_nil, List.nil_append, Nat.zero_add]
  -- Walk the tampered entry at position `l₁.length`: its hash check fails.
  simp only [verifyFrom]
  rw [if_pos (Or.inl hH)]
  simp

/-! ## repair (ledger.rs:276-290) -/

/-- `DecisionLedger::repair`: reseal *every* entry in order, threading
    the recomputed hash. Content fields other than `prevHash` are kept;
    `entryHash` is recomputed. (The model abstracts the `repair_reason`
    string the Rust code stamps on broken entries and the flag fields
    `verify` set — neither participates in the chain.) -/
def repairFrom (H : Nat → Fields → String) (n : Nat) (p : String) :
    List Entry → List Entry
  | [] => []
  | e :: t =>
      let e' := sealAt H n e p
      e' :: repairFrom H (n + 1) e'.entryHash t

def repair (H : Nat → Fields → String) (l : List Entry) : List Entry :=
  repairFrom H 0 "" l

/-- **Repair always restores the chain invariant**, for any input
    whatsoever — matching the Rust behaviour that `verify` is empty after
    `repair` (ledger.rs tests). -/
theorem repairFrom_chain (H : Nat → Fields → String) :
    ∀ {n p} (l : List Entry), Chain H n p (repairFrom H n p l) := by
  intro n p l
  induction l generalizing n p with
  | nil => exact Chain.nil
  | cons e t ih =>
      simp only [repairFrom]
      exact Chain.cons rfl rfl (ih (n := n + 1))

theorem repair_chain (H : Nat → Fields → String) (l : List Entry) :
    Chain H 0 "" (repair H l) :=
  repairFrom_chain H l

/-- **A repaired ledger verifies clean.** -/
theorem verify_repair (H : Nat → Fields → String) (l : List Entry) :
    verify H (repair H l) = [] :=
  verifyFrom_of_chain H (repair_chain H l)

theorem repairFrom_length (H : Nat → Fields → String) :
    ∀ {n p} (l : List Entry), (repairFrom H n p l).length = l.length := by
  intro n p l
  induction l generalizing n p with
  | nil => rfl
  | cons e t ih => simp [repairFrom, ih]

/-- The application content of an entry: everything except the two
    chain-maintained fields (`prevHash` inside `fields`, and
    `entryHash`). -/
def contentOf (e : Entry) : Fields := { e.fields with prevHash := "" }

/-- **Repair preserves all application content and the entry order**:
    it rewrites only the chain fields. Indexes are preserved, as the
    Rust reference requires (ledger.rs:276-278). -/
theorem repairFrom_content (H : Nat → Fields → String) :
    ∀ {n p} (l : List Entry),
      (repairFrom H n p l).map contentOf = l.map contentOf := by
  intro n p l
  induction l generalizing n p with
  | nil => rfl
  | cons e t ih =>
      simp only [repairFrom, List.map_cons]
      have hseal : contentOf (sealAt H n e p) = contentOf e := rfl
      rw [hseal, ih]

/-! ## Consensus replay grading (consensus.rs:25-66) -/

/-- The grade `replay` assigns one decision. -/
inductive Grade where
  | unanimous
  | disputed
  | insufficient
deriving DecidableEq, Repr

/-- One recorded round entry of a decision, reduced to the two things
    `replay` reads from its body (consensus.rs:47-52): the vote
    (`body["vote"]`, absent = `none`) and whether
    `body["payload_echo_confirmed"]` is *explicitly* `false`. -/
abbrev Round := Option String × Bool

/-- `replay`'s per-decision grading (consensus.rs:55-65): `insufficient`
    when any round entry lacks a vote or carries an unconfirmed echo;
    otherwise `unanimous` when the distinct votes number ≤ 1 (the Rust
    sorts and dedups), else `disputed`.

    Note there is no voter identity anywhere in the input: the "quorum"
    is unanimity over recorded round *entries*, and a single agreeing
    entry already grades `unanimous` (see `grade_single`). -/
/- The Rust test `distinct.len() ≤ 1` (after sort + dedup) is the
    decidable predicate "all votes are equal", which is what the model
    checks directly: a list has at most one distinct element iff every
    two of its elements are equal (proved in
    `eq_of_mem_allSameVote` and used in `grade_unanimous_all_eq`). -/
def allSameVote : List String → Bool
  | [] => true
  | v :: t => t.all (fun u => decide (u = v))

def grade (rounds : List Round) : Grade :=
  if rounds.any (fun r => r.1.isNone) || rounds.any (fun r => r.2) then .insufficient
  else if allSameVote (rounds.filterMap (·.1)) then .unanimous
  else .disputed

theorem grade_eq (rounds : List Round) :
    grade rounds = Grade.unanimous ∨ grade rounds = Grade.disputed
      ∨ grade rounds = Grade.insufficient := by
  unfold grade
  split
  · exact Or.inr (Or.inr rfl)
  · split
    · exact Or.inl rfl
    · exact Or.inr (Or.inl rfl)

/-- Missing vote ⇒ insufficient (consensus.rs:55-57). -/
theorem grade_insufficient_of_missing {rounds : List Round} {r : Round}
    (hr : r ∈ rounds) (hv : r.1 = none) : grade rounds = Grade.insufficient := by
  unfold grade
  have h1 : rounds.any (fun r => r.1.isNone) = true := by
    rw [List.any_eq_true]
    exact ⟨r, hr, by simp [hv]⟩
  rw [if_pos (show (rounds.any (fun r => r.1.isNone) || rounds.any (fun r => r.2)) = true
    by simp [h1])]

/-- Unconfirmed payload echo ⇒ insufficient (consensus.rs:50-52, 55). -/
theorem grade_insufficient_of_unconfirmed {rounds : List Round} {r : Round}
    (hr : r ∈ rounds) (he : r.2 = true) : grade rounds = Grade.insufficient := by
  unfold grade
  have h2 : rounds.any (fun r => r.2) = true := by
    rw [List.any_eq_true]
    exact ⟨r, hr, he⟩
  rw [if_pos (show (rounds.any (fun r => r.1.isNone) || rounds.any (fun r => r.2)) = true
    by simp [h2])]

/-- If `allSameVote` holds, every two votes in the list are equal. -/
theorem eq_of_mem_allSameVote {votes : List String} (h : allSameVote votes = true) :
    ∀ a ∈ votes, ∀ b ∈ votes, a = b := by
  cases votes with
  | nil => intro a ha; simp at ha
  | cons v t =>
      intro a ha b hb
      have hall : ∀ u ∈ t, u = v := by
        intro u hu
        have hu2 : (fun u => decide (u = v)) u = true :=
          List.all_eq_true.mp h u hu
        exact of_decide_eq_true hu2
      cases List.mem_cons.mp ha with
      | inl h1 =>
          cases List.mem_cons.mp hb with
          | inl h2 => rw [h1, h2]
          | inr h2 => rw [h1]; exact (hall b h2).symm
      | inr h1 =>
          cases List.mem_cons.mp hb with
          | inl h2 => rw [h2]; exact hall a h1
          | inr h2 => rw [hall a h1, hall b h2]

/-- **What `unanimous` means**: every recorded round entry voted, no
    entry has an unconfirmed echo, and all votes are the *same* string.
    (consensus.rs:55-64.) -/
theorem grade_unanimous_all_eq {rounds : List Round}
    (h : grade rounds = Grade.unanimous) :
    (∀ r ∈ rounds, r.2 = false) ∧
    (∀ r₁ ∈ rounds, ∀ r₂ ∈ rounds, r₁.1 = r₂.1) := by
  unfold grade at h
  have hcond : ¬ ((rounds.any (fun r => r.1.isNone) || rounds.any (fun r => r.2)) = true) := by
    intro hc
    rw [if_pos hc] at h
    exact Grade.noConfusion h
  have hany1 : rounds.any (fun r => r.1.isNone) = false := by
    cases hc : rounds.any (fun r => r.1.isNone) with
    | false => rfl
    | true => exact absurd (by simp [hc]) hcond
  have hany2 : rounds.any (fun r => r.2) = false := by
    cases hc : rounds.any (fun r => r.2) with
    | false => rfl
    | true => exact absurd (by simp [hc]) hcond
  have hsame : allSameVote (rounds.filterMap (·.1)) = true := by
    by_cases hc : allSameVote (rounds.filterMap (·.1)) = true
    · exact hc
    · have hne : ¬ (allSameVote (rounds.filterMap (·.1)) = true) := by
        cases hb : allSameVote (rounds.filterMap (·.1)) with
        | false => simp
        | true => exact absurd hb hc
      rw [if_neg hcond, if_neg hne] at h
      exact Grade.noConfusion h
  constructor
  · intro r hr
    have hne := List.any_eq_false.mp hany2 r hr
    cases hb : r.2 with
    | false => rfl
    | true => exact absurd hb hne
  · intro r₁ hr₁ r₂ hr₂
    obtain ⟨a, ha⟩ : ∃ a, r₁.1 = some a := by
      cases hv : r₁.1 with
      | none =>
          have hne := List.any_eq_false.mp hany1 r₁ hr₁
          simp [hv] at hne
      | some a => exact ⟨a, rfl⟩
    obtain ⟨b, hb⟩ : ∃ b, r₂.1 = some b := by
      cases hv : r₂.1 with
      | none =>
          have hne := List.any_eq_false.mp hany1 r₂ hr₂
          simp [hv] at hne
      | some b => exact ⟨b, rfl⟩
    have hmem_a : a ∈ rounds.filterMap (·.1) :=
      List.mem_filterMap.mpr ⟨r₁, hr₁, ha⟩
    have hmem_b : b ∈ rounds.filterMap (·.1) :=
      List.mem_filterMap.mpr ⟨r₂, hr₂, hb⟩
    have hab : a = b := eq_of_mem_allSameVote hsame a hmem_a b hmem_b
    rw [ha, hb, hab]

/-- **A single dissenting vote defeats unanimity** — acceptance really
    does require every recorded round to agree. -/
theorem grade_ne_unanimous_of_dissent {rounds : List Round} {r₁ r₂ : Round}
    {a b : String} (hr₁ : r₁ ∈ rounds) (hr₂ : r₂ ∈ rounds)
    (hv₁ : r₁.1 = some a) (hv₂ : r₂.1 = some b) (hab : a ≠ b) :
    grade rounds ≠ Grade.unanimous := by
  intro h
  obtain ⟨-, heq⟩ := grade_unanimous_all_eq h
  have h2 := heq r₁ hr₁ r₂ hr₂
  rw [hv₁, hv₂] at h2
  exact hab (Option.some.inj h2)

/-- The minimum "quorum" is one recorded round entry: a lone agreeing,
    confirmed vote grades `unanimous`. -/
theorem grade_single (v : String) : grade [(some v, false)] = Grade.unanimous := by
  simp [grade, allSameVote]

/-- Vacuous case: in the Rust replay this is unreachable (the decisions
    map only contains ids with ≥ 1 `round` entry, consensus.rs:28-35),
    but the grading function itself grades an empty round list
    `unanimous` (no dissent, no missing vote). -/
theorem grade_nil : grade [] = Grade.unanimous := rfl

/-! ## Third-party validation state machine (validators.rs:39-62) -/

/-- The three session statuses the v0.1 transitions use (models.rs:66-76
    has nine; `promote` — which would set `PROVISIONAL_LOCK` — is not in
    v0.1, orchestrator.rs:5-6). -/
inductive Status where
  | exploring
  | provisionalLock
  | locked
deriving DecidableEq, Repr

/-- The parts of `DecisionCase` (models.rs:327-355) that
    `apply_third_party_validation` reads or writes. `tpLog` stores the
    validated item names (the Rust stores whole validation records; only
    their accumulation matters here). -/
structure Case where
  status : Status
  lockedDecisions : List String
  flipCriteria : List String
  tpLog : List String
deriving DecidableEq, Repr

/-- `apply_third_party_validation` (validators.rs:39-62) as a partial
    transition: `none` is the `Err(InvalidTransition)` case, in which
    the Rust returns *before any mutation* (validators.rs:44-48). On
    CONFIRM from `PROVISIONAL_LOCK`: status `LOCKED`, the item appended
    to `locked_decisions` **only if not already present** (dedup,
    validators.rs:54-56). On REJECT: status back to `EXPLORING`, a flip
    criterion appended, `locked_decisions` untouched. Either way the
    validation is appended to the log first (validators.rs:51). -/
def applyTP (c : Case) (item : String) (confirm : Bool) : Option Case :=
  if c.status ≠ Status.provisionalLock then none
  else if confirm then
    some { c with
      status := Status.locked
      lockedDecisions :=
        if item ∈ c.lockedDecisions then c.lockedDecisions
        else c.lockedDecisions ++ [item]
      tpLog := c.tpLog ++ [item] }
  else
    some { c with
      status := Status.exploring
      flipCriteria := c.flipCriteria ++ ["Validation rejected: " ++ item]
      tpLog := c.tpLog ++ [item] }

/-- **Rejected transitions change nothing**: third-party validation from
    any status other than `PROVISIONAL_LOCK` fails outright — in
    particular `LOCKED` is absorbing for this operation. -/
theorem applyTP_none_of_not_provisional {c : Case} (item : String) (confirm : Bool)
    (h : c.status ≠ Status.provisionalLock) : applyTP c item confirm = none := by
  simp [applyTP, h]

theorem applyTP_locked_absorbing {c : Case} (item : String) (confirm : Bool)
    (h : c.status = Status.locked) : applyTP c item confirm = none :=
  applyTP_none_of_not_provisional item confirm (by simp [h])

/-- CONFIRM from `PROVISIONAL_LOCK` locks the case. -/
theorem applyTP_confirm_status {c : Case} (item : String)
    (h : c.status = Status.provisionalLock) :
    (applyTP c item true).map Case.status = some Status.locked := by
  unfold applyTP
  rw [if_neg (by simp [h]), if_pos rfl]
  rfl

/-- …and records the item among the locked decisions. -/
theorem applyTP_confirm_records {c : Case} (item : String)
    (h : c.status = Status.provisionalLock) {c' : Case}
    (h' : applyTP c item true = some c') : item ∈ c'.lockedDecisions := by
  unfold applyTP at h'
  rw [if_neg (by simp [h])] at h'
  rw [if_pos rfl] at h'
  simp only [Option.some.injEq] at h'
  subst h'
  show item ∈ (if item ∈ c.lockedDecisions then c.lockedDecisions
    else c.lockedDecisions ++ [item])
  by_cases hc : item ∈ c.lockedDecisions
  · rw [if_pos hc]; exact hc
  · rw [if_neg hc]
    exact List.mem_append.mpr (Or.inr (List.mem_singleton_self item))

/-- Helper: appending a fresh element preserves `Nodup`. -/
theorem nodup_append_singleton {l : List String} {x : String}
    (hl : l.Nodup) (hx : x ∉ l) : (l ++ [x]).Nodup := by
  induction l with
  | nil =>
      exact List.nodup_cons.mpr ⟨by simp, List.nodup_nil⟩
  | cons a t ih =>
      rw [List.nodup_cons] at hl
      have hx' : x ∉ t := fun h => hx (List.mem_cons_of_mem a h)
      have hax : a ≠ x := by
        intro h
        apply hx
        rw [h]
        exact List.mem_cons_self
      simp only [List.cons_append, List.nodup_cons]
      refine ⟨fun hmem => ?_, ih hl.2 hx'⟩
      cases List.mem_append.mp hmem with
      | inl h => exact hl.1 h
      | inr h => exact hax (List.mem_singleton.mp h)

/-- **Locked decisions never duplicate**: `locked_decisions` stays
    duplicate-free across a CONFIRM (the code's `contains` check,
    validators.rs:54-56). -/
theorem applyTP_confirm_nodup {c : Case} (item : String)
    (h : c.status = Status.provisionalLock) (hl : c.lockedDecisions.Nodup) {c' : Case}
    (h' : applyTP c item true = some c') : c'.lockedDecisions.Nodup := by
  unfold applyTP at h'
  rw [if_neg (by simp [h])] at h'
  rw [if_pos rfl] at h'
  simp only [Option.some.injEq] at h'
  subst h'
  show (if item ∈ c.lockedDecisions then c.lockedDecisions
    else c.lockedDecisions ++ [item]).Nodup
  by_cases hc : item ∈ c.lockedDecisions
  · rw [if_pos hc]; exact hl
  · rw [if_neg hc]
    exact nodup_append_singleton hl hc

/-- REJECT from `PROVISIONAL_LOCK`: back to `EXPLORING`, locked decisions
    untouched, exactly one flip criterion appended naming the item. -/
theorem applyTP_reject {c : Case} (item : String)
    (h : c.status = Status.provisionalLock) {c' : Case}
    (h' : applyTP c item false = some c') :
    c'.status = Status.exploring ∧ c'.lockedDecisions = c.lockedDecisions ∧
      c'.flipCriteria = c.flipCriteria ++ ["Validation rejected: " ++ item] ∧
      c'.tpLog = c.tpLog ++ [item] := by
  unfold applyTP at h'
  rw [if_neg (by simp [h])] at h'
  rw [if_neg (by decide)] at h'
  simp only [Option.some.injEq] at h'
  subst h'
  exact ⟨rfl, rfl, rfl, rfl⟩

/-! ## R0 session gate (gates.rs:38-55) -/

/-- The R0 verdict as a Bool (the Rust parameters are `solvable`,
    `scoped`, `valid`, `worth_it`, in this order): `PASS` iff all four
    checks pass, else `HALT`. The orchestrator refuses to open a case
    (and writes no ledger) unless the verdict is `PASS`
    (orchestrator.rs:58-63). -/
def r0Pass (a b c d : Bool) : Bool :=
  a && b && c && d

theorem r0Pass_iff (a b c d : Bool) :
    r0Pass a b c d = true ↔ a = true ∧ b = true ∧ c = true ∧ d = true := by
  cases a <;> cases b <;> cases c <;> cases d <;> simp [r0Pass]

theorem r0Pass_false_of_any (a b c d : Bool)
    (h : a = false ∨ b = false ∨ c = false ∨ d = false) :
    r0Pass a b c d = false := by
  cases a <;> cases b <;> cases c <;> cases d <;> simp_all [r0Pass]

/-! ## Foundation floors (foundation.rs:13-66) -/

/-- `foundation_floor` (foundation.rs:23-47) on the already-normalised
    key (the Rust trims and lowercases first): exact matches gate at
    their floor; everything else at the default 70. (The Rust's
    near-match *warning* for unlisted look-alikes does not change the
    returned floor.) -/
def foundationFloor (key : String) : Nat :=
  if key = "blockchain" ∨ key = "defi" then 85
  else if key = "finance" ∨ key = "cfo" ∨ key = "capital_allocation"
      ∨ key = "board_decision" then 100
  else 70

/-- The floor is always one of 70 / 85 / 100 — in particular an unknown
    domain never gates at 0 (foundation.rs:9-10). -/
theorem foundationFloor_range (key : String) :
    foundationFloor key = 70 ∨ foundationFloor key = 85 ∨ foundationFloor key = 100 := by
  unfold foundationFloor
  split
  · exact Or.inr (Or.inl rfl)
  · split
    · exact Or.inr (Or.inr rfl)
    · exact Or.inl rfl

theorem foundationFloor_ge (key : String) : 70 ≤ foundationFloor key := by
  have h := foundationFloor_range key
  rcases h with h | h | h <;> omega

theorem foundationFloor_finance : foundationFloor "finance" = 100 := by decide
theorem foundationFloor_blockchain : foundationFloor "blockchain" = 85 := by decide
theorem foundationFloor_general : foundationFloor "general" = 70 := by decide

/-- Unknown domains (not one of the nine listed names) gate at the
    default floor 70. -/
theorem foundationFloor_unknown {key : String}
    (h1 : key ≠ "blockchain") (h2 : key ≠ "defi") (h3 : key ≠ "finance")
    (h4 : key ≠ "cfo") (h5 : key ≠ "capital_allocation")
    (h6 : key ≠ "board_decision") :
    foundationFloor key = 70 := by
  unfold foundationFloor
  rw [if_neg (by simp [h1, h2]), if_neg (by simp [h3, h4, h5, h6])]

/-- `foundation_verdict` (foundation.rs:60-66) as a Bool: PASS iff the
    score reaches the domain floor. -/
def foundationPass (score : Nat) (key : String) : Bool :=
  decide (foundationFloor key ≤ score)

theorem foundationPass_finance (score : Nat) :
    foundationPass score "finance" = true ↔ 100 ≤ score := by
  simp [foundationPass, foundationFloor_finance]

/-! ## SwarmFi gate quorum (swarmfi_gate.rs:36-61) -/

/-- The SwarmFi gate's verdicts (swarmfi_gate.rs:10-16). -/
inductive SwarmVerdict where
  | noData
  | pass
  | splitDamped
deriving DecidableEq, Repr

/-- The SwarmFi gate reduced to its quorum structure: the verdict and
    whether a weighted median is produced depend on the *number* of
    votes `n` and (for `n ≥ 3`) whether a split was detected. The f64
    median/damping arithmetic itself is abstracted into the `split`
    input — the safety-relevant rule is the count quorum:
    `MIN_SOURCES = 3` (swarmfi_gate.rs:36): fewer than three votes →
    `NO_DATA` and no median, regardless of weights or values. Note the
    code counts slice *entries*; nothing identifies "independent
    sources" (see NOTES.md). -/
def swarmGate (n : Nat) (split : Bool) : SwarmVerdict × Option Unit :=
  if n < 3 then (SwarmVerdict.noData, none)
  else (if split then SwarmVerdict.splitDamped else SwarmVerdict.pass, some ())

/-- **Below quorum, no decision**: fewer than 3 votes ⇒ `NO_DATA` and
    no median, for any split input. -/
theorem swarm_noData_of_lt_three {n : Nat} (h : n < 3) (split : Bool) :
    swarmGate n split = (SwarmVerdict.noData, none) := by
  simp [swarmGate, h]

/-- **At quorum, a median is always produced** and the verdict is a real
    decision (`PASS` or `SPLIT_DAMPED`). -/
theorem swarm_decides_of_ge_three {n : Nat} (h : 3 ≤ n) (split : Bool) :
    (swarmGate n split).2 = some () ∧ (swarmGate n split).1 ≠ SwarmVerdict.noData := by
  unfold swarmGate
  rw [if_neg (by omega)]
  cases split <;> simp

/-- The `NO_DATA` verdict is *exactly* the below-quorum case. -/
theorem swarm_noData_iff {n : Nat} (split : Bool) :
    (swarmGate n split).1 = SwarmVerdict.noData ↔ n < 3 := by
  unfold swarmGate
  by_cases h : n < 3
  · rw [if_pos h]
    exact Iff.intro (fun _ => h) (fun _ => rfl)
  · rw [if_neg h]
    cases split <;> simp [h]

end ChpCore
