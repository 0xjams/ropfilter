import pytest
from ropfilter.classify import classify_gadget

def test_default_write_records_and_lists_unclassified_setcc_bswap_shift():
    from ropfilter.utils import set_exact_reg_mode
    set_exact_reg_mode(True)
    g = classify_gadget(0x500000, [
        "setnz al",        # writes al (byte reg), typically not explicitly handled
        "bswap eax",       # writes eax; one-operand writer
        "shl ecx, 1",      # shift writes dst
        "bt edx, 3",       # bit test/modify class
        "rcr ebx, cl",     # rotate through carry
    ])

    # Fallback should have created arith entries for each with dst and idx
    ops = { (a.get("op"), a.get("dst")) for a in g.arith }
    #print(g.unclassified_reg_writes)
    assert ("setnz", "al") in ops
    assert ("bswap", "eax") in ops
    assert ("shl", "ecx") in ops
    assert ("bt", "edx") in ops

    # dst registers appear in clobbers
    for reg in ["al","eax","ecx","edx","ebx"]:
        assert any(c.lower() == reg for c in g.clobbers)

    # audit list exists and contains our lines
    assert hasattr(g, "unclassified_reg_writes")
    print(g.unclassified_reg_writes)
    mns = [t['op'].lower() for t in g.unclassified_reg_writes]
    assert "setnz" in mns and "bswap" in mns and "shl" in mns and "bt" in mns 

def test_default_write_with_imm_and_reg_sources():
    g = classify_gadget(0x500100, [
        "movd eax, 1",
        "movq ecx, edx",
    ])
    # fallback should capture src_imm and src accordingly
    print(g.arith)
    had_adc = any(a.get("op")=="movd" and a.get("dst")=="eax" and a.get("imm")==1 for a in g.arith)
    had_sbb = any(a.get("op")=="movq" and a.get("dst")=="ecx" and a.get("src")=="edx" for a in g.arith)
    assert had_adc and had_sbb

def test_default_write_skips_when_existing_classifier_handles_it():
    # 'xor eax, eax' is handled by your normal arithmetic classifier
    g = classify_gadget(0x500200, [
        "xor eax, eax"
    ])
    # Should NOT appear as unclassified
    assert not getattr(g, "unclassified_reg_writes", [])
    # And still produce a normal arith entry
    assert any(a.get("op")=="xor" and a.get("dst")=="eax" for a in g.arith)
