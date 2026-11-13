//! Local BIN replaces container acquisition, not FlashHandler's operation state.
use crate::n20_partial::PartialImage;
use serde_json::{json, Value};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Mode {
    P,
    PF,
    F,
    FF,
    U,
    UF,
    L,
    LF,
}
impl Mode {
    pub(crate) fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "P" => Self::P,
            "PF" => Self::PF,
            "F" => Self::F,
            "FF" => Self::FF,
            "U" => Self::U,
            "UF" => Self::UF,
            "L" => Self::L,
            "LF" => Self::LF,
            _ => return None,
        })
    }
    fn unlock(self) -> bool {
        matches!(self, Self::U | Self::UF)
    }
    fn relock(self) -> bool {
        matches!(self, Self::L | Self::LF)
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::P => "P",
            Self::PF => "PF",
            Self::F => "F",
            Self::FF => "FF",
            Self::U => "U",
            Self::UF => "UF",
            Self::L => "L",
            Self::LF => "LF",
        }
    }
}
#[derive(Default, Clone)]
pub(crate) struct AgentState {
    pub unlock_done: Option<bool>,
    pub last_flash_success: Option<bool>,
    pub needs_recovery: Option<bool>,
    pub last_flash_type: Option<String>,
}
#[derive(Default)]
pub(crate) struct MapCapabilities {
    pub unlock_available: Option<bool>,
    pub relock_available: Option<bool>,
    pub unlock_startup: bool,
    pub tuned_startup: bool,
    pub stock_startup: bool,
}
pub(crate) struct LocalBinInput {
    pub image: PartialImage,
    pub vin: String,
    pub requested: Mode,
    pub target_bootloader: Option<String>,
    pub target_software: String,
    pub target_calibration: Option<String>,
    pub metadata: Value,
    pub stock: Option<bool>,
    pub capabilities: MapCapabilities,
}
impl LocalBinInput {
    pub fn new(image: PartialImage, vin: &str, requested: Mode) -> Result<Self, String> {
        if vin.len() != 17
            || !vin.bytes().all(|b| {
                b.is_ascii_uppercase() && !matches!(b, b'I' | b'O' | b'Q') || b.is_ascii_digit()
            })
        {
            return Err("Local flash context requires a valid selected VIN".into());
        }
        let token = image.calibration_token();
        let calibration = if token == "00".repeat(7) || token == "FF".repeat(7) {
            None
        } else {
            Some(token)
        };
        let metadata = crate::n20_bin_metadata::inspect(image.bytes())?;
        Ok(Self {
            target_software: image.software_token.clone(),
            target_calibration: calibration,
            image,
            vin: vin.into(),
            requested,
            target_bootloader: metadata.bootloader,
            metadata: metadata.report,
            capabilities: Default::default(),
            stock: None,
        })
    }
    pub fn manifest(&self) -> Value {
        json!({"schema":"n20-local-bin-input-v1","source":"local-bin","vin":self.vin,
            "vin_provenance":"selected vehicle context; not extracted from filename or authenticated in BIN",
            "requested_agent_type":self.requested.name(),"bin_sha256":self.image.sha256,
            "image_length":self.image.bytes().len(),"candidate_family":"MEVD17.2.9",
            "target":{"software_token":self.target_software,"software_file_offset":0x20025,
                "calibration_token":self.target_calibration,"calibration_file_offset":0x1ffd01,
                "bootloader":self.target_bootloader,"coding":Value::Null,
                "provenance":"BIN bytes; missing fields are not copied from current DME"},"bin_metadata":self.metadata,
            "startup_payloads":{"unlock":self.capabilities.unlock_startup,"tuned":self.capabilities.tuned_startup,"stock":self.capabilities.stock_startup},
            "stock_classification":self.stock,"stock_provenance":"explicit local user classification, not authenticated map metadata",
            "container_decode_required":false,"programming_approved":false})
    }
}

pub(crate) struct Decision {
    pub selected: Option<Mode>,
    pub report: Value,
}
pub(crate) fn compact(value: &str) -> Option<String> {
    if value.len() != 17 || !value.is_ascii() || !value[..8].bytes().all(|b| b.is_ascii_hexdigit())
    {
        return None;
    }
    let mut out = value[..8].to_ascii_uppercase();
    for offset in [8, 11, 14] {
        let text = &value[offset..offset + 3];
        if !text.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        out.push_str(&format!("{:02X}", text.parse::<u8>().ok()?));
    }
    Some(out)
}
/// Local ordinary BIN intent has no legacy cached-unlock prerequisite. Access
/// must still be established by n20_setup on the actual programming channel.
pub(crate) fn choose_for_bin(
    root: &std::path::Path,
    input: &LocalBinInput,
    vin: &str,
    live: &crate::n20_agent_state::Identity,
    legacy: &AgentState,
    status: &crate::n20_preflight_status::Status,
) -> Result<Decision, String> {
    if crate::n20_agent_state::has_saved_state(root, vin)? {
        let mut decision = select_with_status(
            input,
            vin,
            &live.bootloader_id,
            &live.software_id,
            legacy,
            status,
        );
        decision.report["routing_basis"] = json!("imported-agent-history");
        return Ok(decision);
    }
    let safety = crate::n20_operation_history::startup_review(root)?;
    let mut missing = Vec::new();
    if safety["blocked"] != false {
        missing.push("Uncertain local operation history requires review before selecting an ordinary BIN route");
    }
    if input.vin != vin
        || [
            &live.hardware_id,
            &live.bootloader_id,
            &live.software_id,
            &live.calibration_id,
        ]
        .iter()
        .any(|id| compact(id).is_none())
    {
        missing.push("Fresh DME identity is incomplete or differs from the selected vehicle");
    }
    if !matches!(input.requested, Mode::P | Mode::F) {
        missing.push("Only ordinary calibration or software/calibration intent is supported without legacy agent state");
    }
    match input.target_bootloader.as_deref(){
        None=>missing.push("Required bootloader identity is unavailable in this BIN"),
        Some(target) if !target.eq_ignore_ascii_case(&live.bootloader_id)=>missing.push("BIN requires a different bootloader; startup programming is outside this local BIN operation"),
        _=>{},
    }
    if live.bootloader_id.eq_ignore_ascii_case("00005BA6011019002") {
        missing.push("The selected bootloader is excluded by the retained support check");
    }
    if input.requested == Mode::P
        && compact(&live.software_id).as_deref() != Some(input.target_software.as_str())
    {
        missing.push("Calibration-only BIN software differs from the DME; review the software/calibration mode and exact compatibility");
    }
    if input
        .target_calibration
        .as_ref()
        .and_then(|v| crate::n20_bin_metadata::decimal(v))
        .is_none()
    {
        missing.push("BIN calibration identity is unavailable");
    }
    let selected = if missing.is_empty() {
        Some(input.requested)
    } else {
        None
    };
    Ok(Decision {
        selected,
        report: json!({"schema":"n20-agent-dispatch-v1","routing_basis":"bimmerscope-local-bin",
        "requested":input.requested.name(),"candidate":input.requested.name(),"selected":selected.map(Mode::name),"resolved":selected.is_some(),
        "route":if input.requested==Mode::P{"partial"}else{"full-software-calibration"},"force":false,"stock_classification":input.stock,
        "agent_state":{"unlockDone":Value::Null,"lastFlashSuccess":Value::Null,"needsRecovery":Value::Null,"lastFlashType":Value::Null},
        "missing_requirements":missing,"trace":["Ordinary local BIN intent selected from fresh identity and inspected local history","Programming session and security access must be established on the owned write connection before fingerprint or erase"],
        "programming_access_verified":false,"persistent_unlock_verified":false,"programming_approved":false,
        "requires_fresh_owned_security":true,"limits":"Route selection only. No imported agent state is invented. Compatibility, exact profile, live conditions/power and same-connection security remain mandatory; no startup unlock/relock or automatic recovery."}),
    })
}
/// N20 legacy generic main dispatch, ia.java 734-839, with the version-rewrite
/// subset at 495-528. Other preflight recovery/status overrides are explicit gaps.
pub(crate) fn select(
    input: &LocalBinInput,
    live_vin: &str,
    live_bootloader: &str,
    live_software: &str,
    state: &AgentState,
) -> Decision {
    select_with_status(
        input,
        live_vin,
        live_bootloader,
        live_software,
        state,
        &crate::n20_preflight_status::Status::Unavailable,
    )
}
pub(crate) fn select_with_status(
    input: &LocalBinInput,
    live_vin: &str,
    live_bootloader: &str,
    live_software: &str,
    state: &AgentState,
    status: &crate::n20_preflight_status::Status,
) -> Decision {
    let mut mode = input.requested;
    let mut force = false;
    let mut version_override = false;
    let mut trace = vec![];
    let mut missing = vec![];
    if input.vin != live_vin {
        missing.push("Selected context VIN differs from fresh DME VIN");
    }
    if compact(live_software).is_none() || compact(live_bootloader).is_none() {
        missing.push("Fresh DME software/bootloader is malformed");
    }
    // bo.isValid requires target BTLD, software and calibration, not coding.
    let target_valid = input
        .target_bootloader
        .as_ref()
        .is_some_and(|value| compact(value).is_some())
        && crate::n20_bin_metadata::decimal(&input.target_software).is_some()
        && input
            .target_calibration
            .as_ref()
            .is_some_and(|value| crate::n20_bin_metadata::decimal(value).is_some());
    if input
        .target_bootloader
        .as_ref()
        .is_some_and(|value| compact(value).is_none())
    {
        missing.push("Present target bootloader ID is malformed");
    }
    if live_bootloader.eq_ignore_ascii_case("00005BA6011019002") {
        missing
            .push("Legacy agent rejects bootloader 00005BA6-011.019.002 with unlockIgnore=false");
    }
    if !mode.unlock() && !mode.relock() && target_valid {
        if !input
            .target_bootloader
            .as_ref()
            .unwrap()
            .eq_ignore_ascii_case(live_bootloader)
        {
            mode = Mode::UF;
            version_override = true;
            trace.push("Target bootloader differs: agent preflight requests UF");
        }
    } else if !target_valid {
        trace.push(
            "Target map identity is incomplete; agent mp version comparison is not established",
        );
    }
    // ia preflight status branch runs before the worker's unlock/recovery rewrite.
    // Its version-mismatch branch jumps past this status override block.
    if !version_override
        && state.needs_recovery == Some(true)
        && !matches!(mode, Mode::FF | Mode::PF | Mode::UF | Mode::LF | Mode::L)
    {
        use crate::n20_preflight_status::Status;
        match status{
            Status::Unavailable=>missing.push("A recent identity-bound explicit condition query is required for agent recovery preflight"),
            Status::Text(text) if text.to_ascii_uppercase().contains("HIS")=>missing.push("Legacy HIS precondition status stops before programming; cause and remedy require independent validation"),
            Status::FailedQuery=>{
                force=true;
                trace.push("Agent preflight status=fail sets force=true; independent programming gates remain mandatory");
                if let Some(last)=state.last_flash_type.as_deref(){
                    match input.stock{
                        None=>missing.push("Stock/modified BIN classification is unavailable for prior-type recovery selection"),
                        Some(true)=>{mode=if matches!(Mode::parse(last),Some(Mode::L|Mode::LF)){Mode::LF}else{Mode::FF};},
                        Some(false)=>match Mode::parse(last){
                            Some(Mode::L|Mode::LF)=>mode=Mode::UF,
                            Some(last)=>mode=last,
                            None=>missing.push("Saved agent last flash type has no implemented local-BIN route"),
                        },
                    }
                }else{
                    // L/LF are excluded from this block, so the stock+relock
                    // fallback is unreachable here in the retained control flow.
                    mode=if state.unlock_done==Some(true) && !mode.unlock(){Mode::FF}else{Mode::UF};
                    if state.unlock_done.is_none(){missing.push("Unlock confirmation is unavailable for no-prior-type failure fallback");}
                }
            },
            Status::Text(_)=>trace.push("Empty/other status: agent preflight leaves force and type unchanged"),
        }
    }
    match state.unlock_done {
        None if !mode.relock() && mode != Mode::U => missing.push(
            "Agent saved unlockDone state is unavailable; no false/true default is substituted",
        ),
        Some(false) if !mode.relock() => {
            mode = Mode::U;
            trace.push("unlockDone=false: agent selects U before normal partial/full dispatch");
        }
        _ => {}
    }
    if state.unlock_done == Some(true) && !mode.unlock() && !mode.relock() {
        match (state.last_flash_success,state.needs_recovery) {
            (Some(false),Some(true))=>{mode=Mode::F;trace.push("Failed previous flash with needsRecovery=true: agent selects F");},
            (Some(true),_)|(_,Some(false))=>{},
            _=>missing.push("Agent lastFlashSuccess/needsRecovery state is insufficient to select the normal path"),
        }
    }
    if matches!(mode, Mode::F | Mode::FF)
        && input.capabilities.unlock_available == Some(true)
        && input.capabilities.unlock_startup
        && input.capabilities.tuned_startup
    {
        mode = Mode::U;
        trace.push("Unlock-capable map with unlock/tuned payloads: agent full path selects U");
    }
    if mode.unlock() {
        if input.capabilities.unlock_available != Some(true) {
            missing.push("Agent U/UF requires map unlock capability (ul)");
        }
        if !input.capabilities.unlock_startup || !input.capabilities.tuned_startup {
            missing.push("Separate unlock and tuned startup payloads are unavailable; ordinary BIN bytes are not substituted");
        }
    }
    if mode.relock() {
        if input.capabilities.relock_available != Some(true) {
            missing.push("Agent L/LF requires map relock capability (l)");
        }
        if !input.capabilities.stock_startup {
            missing.push("Reviewed stock startup payload is unavailable");
        }
    }
    let selected = if missing.is_empty() { Some(mode) } else { None };
    let route = match mode {
        Mode::P | Mode::PF => "partial",
        Mode::F | Mode::FF => "full-software-calibration",
        Mode::U | Mode::UF => "unlock",
        Mode::L | Mode::LF => "relock",
    };
    Decision {
        selected,
        report: json!({"schema":"n20-agent-dispatch-v1","requested":input.requested.name(),
        "candidate":mode.name(),"selected":selected.map(Mode::name),"route":route,"resolved":selected.is_some(),
        "force":force,"stock_classification":input.stock,"preflight_status":match status{crate::n20_preflight_status::Status::Unavailable=>None,crate::n20_preflight_status::Status::FailedQuery=>Some("fail"),crate::n20_preflight_status::Status::Text(text)=>Some(text.as_str())},
        "agent_state":{"unlockDone":state.unlock_done,"lastFlashSuccess":state.last_flash_success,"needsRecovery":state.needs_recovery,"lastFlashType":state.last_flash_type},
        "trace":trace,"missing_requirements":missing,"programming_approved":false,
        "limits":"Legacy single-N20 dispatch subset with unlockIgnore=false, version and status/force overrides followed by worker rewrites. Force is historical selection state, not a gate bypass. Invalid live-identity recovery and live unlock/relock payload paths remain unimplemented."}),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    const VIN: &str = "WBA3A52010F360747";
    const BTLD: &str = "00001901001049002";
    const SW: &str = "00001C9F029150001";
    fn input(mode: Mode) -> LocalBinInput {
        let mut b = vec![0; 0x400000];
        b[26..36].copy_from_slice(b"MEVD1729__");
        for (p, v) in [
            (0x18000c, 0x801ffc00u32),
            (0x180038, 0x80180000),
            (0x18003c, 0x801ffbff),
        ] {
            b[p..p + 4].copy_from_slice(&v.to_le_bytes());
        }
        b[0x20024] = 8;
        b[0x20025..0x2002c].copy_from_slice(&[0, 0, 0x1c, 0x9f, 0x1d, 0x96, 1]);
        b[0x1ffd00] = 8;
        b[0x1ffd01..0x1ffd08].copy_from_slice(&[0, 0, 0x1c, 0xdb, 0x1d, 0x96, 7]);
        let hash = format!("{:x}", Sha256::digest(&b));
        LocalBinInput::new(PartialImage::from_bin(b, &hash).unwrap(), VIN, mode).unwrap()
    }
    fn known() -> AgentState {
        AgentState {
            unlock_done: Some(true),
            last_flash_success: Some(true),
            needs_recovery: Some(false),
            last_flash_type: None,
        }
    }
    #[test]
    fn bin_adapter_preserves_bytes_and_does_not_invent_target_bootloader_or_vin() {
        let input = input(Mode::P);
        let report = input.manifest();
        assert_eq!(report["target"]["software_token"], "00001C9F1D9601");
        assert!(report["target"]["bootloader"].is_null());
        assert_eq!(report["image_length"], 0x400000);
        assert_eq!(
            &input.image.bytes()[0x20025..0x2002c],
            &[0, 0, 0x1c, 0x9f, 0x1d, 0x96, 1]
        );
    }
    #[test]
    fn known_agent_state_routes_partial_and_full_without_calling_either_approved() {
        for mode in [Mode::P, Mode::PF, Mode::F, Mode::FF] {
            let decision = select(&input(mode), VIN, BTLD, SW, &known());
            assert_eq!(decision.selected, Some(mode));
            assert_eq!(decision.report["programming_approved"], false);
        }
    }
    #[test]
    fn unknown_state_stays_unknown_and_false_unlock_state_requires_missing_unlock_payloads() {
        let input = input(Mode::P);
        assert!(select(&input, VIN, BTLD, SW, &AgentState::default())
            .selected
            .is_none());
        let mut state = known();
        state.unlock_done = Some(false);
        let decision = select(&input, VIN, BTLD, SW, &state);
        assert_eq!(decision.report["candidate"], "U");
        assert!(decision.selected.is_none());
    }
    #[test]
    fn prior_failure_selects_full_and_full_with_unlock_payloads_selects_unlock() {
        let mut state = known();
        state.last_flash_success = Some(false);
        state.needs_recovery = Some(true);
        let mut input = input(Mode::P);
        assert_eq!(
            select_with_status(
                &input,
                VIN,
                BTLD,
                SW,
                &state,
                &crate::n20_preflight_status::Status::Text(String::new())
            )
            .selected,
            Some(Mode::F)
        );
        input.capabilities = MapCapabilities {
            unlock_available: Some(true),
            unlock_startup: true,
            tuned_startup: true,
            ..Default::default()
        };
        assert_eq!(
            select_with_status(
                &input,
                VIN,
                BTLD,
                SW,
                &state,
                &crate::n20_preflight_status::Status::Text(String::new())
            )
            .selected,
            Some(Mode::U)
        );
        input.requested = Mode::U;
        assert_eq!(
            select(&input, VIN, BTLD, SW, &AgentState::default()).selected,
            Some(Mode::U)
        );
    }
    #[test]
    fn target_bootloader_mismatch_rewrites_mode_and_relock_requires_explicit_payloads() {
        let mut partial = input(Mode::P);
        partial.target_bootloader = Some("00001901001049003".into());
        assert_eq!(
            select(&partial, VIN, BTLD, SW, &known()).report["candidate"],
            "UF"
        );
        for mode in [Mode::L, Mode::LF] {
            let mut input = input(mode);
            assert!(select(&input, VIN, BTLD, SW, &known()).selected.is_none());
            input.capabilities.relock_available = Some(true);
            input.capabilities.stock_startup = true;
            assert_eq!(
                select(&input, VIN, BTLD, SW, &AgentState::default()).selected,
                Some(mode)
            );
        }
    }
    #[test]
    fn vin_mismatch_and_missing_recovery_flags_never_resolve() {
        let input = input(Mode::P);
        assert!(select(&input, "WBA3A52010F360748", BTLD, SW, &known())
            .selected
            .is_none());
        assert!(select(
            &input,
            VIN,
            BTLD,
            SW,
            &AgentState {
                unlock_done: Some(true),
                ..Default::default()
            }
        )
        .selected
        .is_none());
    }
    #[test]
    fn metadata_gate_compares_bootloader_not_software_or_calibration_equality() {
        let mut input = input(Mode::P);
        input.target_bootloader = Some(BTLD.into());
        input.target_software = "00001C9F1D9602".into();
        input.target_calibration = Some("00001CDB1D9607".into());
        assert_eq!(
            select(&input, VIN, BTLD, SW, &known()).selected,
            Some(Mode::P)
        );
        input.target_bootloader = Some("00001901001049003".into());
        let different = select(&input, VIN, BTLD, SW, &known());
        assert_eq!(different.report["candidate"], "UF");
        assert!(different.selected.is_none());
        input.target_bootloader = Some("malformed".into());
        assert!(select(&input, VIN, BTLD, SW, &known()).selected.is_none());
        input.target_bootloader = Some("00005BA6011019002".into());
        assert!(select(&input, VIN, "00005BA6011019002", SW, &known())
            .selected
            .is_none());
    }
    #[test]
    fn failure_fallback_matrix_preserves_preflight_then_worker_order() {
        use crate::n20_preflight_status::Status;
        let mut state = known();
        state.needs_recovery = Some(true);
        let mut input = input(Mode::P);
        for (prior, modified, stock) in [
            ("P", "P", "FF"),
            ("PF", "PF", "FF"),
            ("F", "F", "FF"),
            ("FF", "FF", "FF"),
            ("U", "U", "FF"),
            ("UF", "UF", "FF"),
            ("L", "UF", "LF"),
            ("LF", "UF", "LF"),
        ] {
            state.last_flash_type = Some(prior.into());
            for (classification, expected) in [(false, modified), (true, stock)] {
                input.stock = Some(classification);
                let d = select_with_status(&input, VIN, BTLD, SW, &state, &Status::FailedQuery);
                assert_eq!(
                    d.report["candidate"], expected,
                    "{prior} stock={classification}"
                );
                assert_eq!(d.report["force"], true);
                assert_eq!(d.report["programming_approved"], false);
                if ["U", "UF", "L", "LF"].contains(&expected) {
                    assert!(d.selected.is_none());
                }
            }
        }
        state.last_flash_type = None;
        input.stock = None;
        assert_eq!(
            select_with_status(&input, VIN, BTLD, SW, &state, &Status::FailedQuery).selected,
            Some(Mode::FF)
        );
        state.last_flash_type = Some("PF".into());
        input.stock = Some(false);
        state.last_flash_success = Some(false);
        let rewritten = select_with_status(&input, VIN, BTLD, SW, &state, &Status::FailedQuery);
        assert_eq!(rewritten.selected, Some(Mode::F));
        assert_eq!(rewritten.report["force"], true);
    }
    #[test]
    fn status_missing_his_unknown_prior_and_exempt_modes_remain_distinct() {
        use crate::n20_preflight_status::Status;
        let mut state = known();
        state.needs_recovery = Some(true);
        state.last_flash_type = Some("P".into());
        let mut input = input(Mode::P);
        assert!(select(&input, VIN, BTLD, SW, &state).selected.is_none());
        assert!(
            select_with_status(&input, VIN, BTLD, SW, &state, &Status::FailedQuery)
                .selected
                .is_none()
        ); // unknown stock
        for text in ["", "engine running. ", "manufacturer reserved "] {
            let d = select_with_status(&input, VIN, BTLD, SW, &state, &Status::Text(text.into()));
            assert_eq!(d.selected, Some(Mode::P));
            assert_eq!(d.report["force"], false);
        }
        assert!(select_with_status(
            &input,
            VIN,
            BTLD,
            SW,
            &state,
            &Status::Text("HIS reserved ".into())
        )
        .selected
        .is_none());
        input.stock = Some(false);
        state.last_flash_type = Some("C".into());
        assert!(
            select_with_status(&input, VIN, BTLD, SW, &state, &Status::FailedQuery)
                .selected
                .is_none()
        );
        input.stock = Some(true);
        assert_eq!(
            select_with_status(&input, VIN, BTLD, SW, &state, &Status::FailedQuery).selected,
            Some(Mode::FF)
        );
        for mode in [Mode::FF, Mode::PF, Mode::UF, Mode::LF, Mode::L] {
            input.requested = mode;
            let d = select(&input, VIN, BTLD, SW, &state);
            assert_eq!(d.report["force"], false);
            assert!(!d.report["missing_requirements"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v.as_str().unwrap().contains("condition query")));
        }
        input.requested = Mode::P;
        input.target_bootloader = Some("00001901001049003".into());
        let d = select(&input, VIN, BTLD, SW, &state);
        assert_eq!(d.report["candidate"], "UF");
        assert!(!d.report["missing_requirements"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v.as_str().unwrap().contains("condition query")));
    }
    #[test]
    fn ordinary_bin_without_agent_cache_keeps_unknown_flags_and_requires_real_write_access() {
        let root = std::env::temp_dir().join(format!(
            "n20-native-route-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let live = crate::n20_agent_state::Identity {
            hardware_id: "000019A6001019003".into(),
            bootloader_id: BTLD.into(),
            software_id: SW.into(),
            calibration_id: "00001CDB029150003".into(),
        };
        let state = AgentState::default();
        let status = crate::n20_preflight_status::Status::Unavailable;
        let mut input = input(Mode::P);
        input.target_bootloader = Some(BTLD.into());
        let d = choose_for_bin(&root, &input, VIN, &live, &state, &status).unwrap();
        assert_eq!(d.selected, Some(Mode::P));
        assert!(d.report["agent_state"]["unlockDone"].is_null());
        assert_eq!(d.report["requires_fresh_owned_security"], true);
        assert_eq!(d.report["programming_approved"], false);
        input.target_software = "00001C9F1D9602".into();
        assert!(choose_for_bin(&root, &input, VIN, &live, &state, &status)
            .unwrap()
            .selected
            .is_none());
        input.requested = Mode::F;
        assert_eq!(
            choose_for_bin(&root, &input, VIN, &live, &state, &status)
                .unwrap()
                .selected,
            Some(Mode::F)
        );
        input.target_bootloader = Some("00001901001049003".into());
        assert!(choose_for_bin(&root, &input, VIN, &live, &state, &status)
            .unwrap()
            .selected
            .is_none());
        input.target_bootloader = Some(BTLD.into());
        let folder = root.join("n20_flash_operations/unknown-operation");
        std::fs::create_dir_all(&folder).unwrap();
        std::fs::write(folder.join("prewrite-approval.json"), b"{}").unwrap();
        assert!(choose_for_bin(&root, &input, VIN, &live, &state, &status)
            .unwrap()
            .selected
            .is_none());
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn malformed_existing_agent_state_cannot_silently_use_no_cache_route() {
        let root = std::env::temp_dir().join(format!(
            "n20-import-route-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let directory = root.join("n20_agent_state").join(VIN);
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(directory.join("corrupt.json"), b"{}").unwrap();
        let live = crate::n20_agent_state::Identity {
            hardware_id: "000019A6001019003".into(),
            bootloader_id: BTLD.into(),
            software_id: SW.into(),
            calibration_id: "00001CDB029150003".into(),
        };
        let loaded = crate::n20_agent_state::load(&root, VIN, &live);
        let mut input = input(Mode::P);
        input.target_bootloader = Some(BTLD.into());
        let d = choose_for_bin(
            &root,
            &input,
            VIN,
            &live,
            &loaded.state,
            &crate::n20_preflight_status::Status::Unavailable,
        )
        .unwrap();
        assert!(d.selected.is_none());
        assert_eq!(d.report["routing_basis"], "imported-agent-history");
        std::fs::remove_dir_all(root).unwrap();
    }
}
