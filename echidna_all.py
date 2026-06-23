"""Echidna stateful fuzzer runner — tests ALL money contracts one by one."""
import os, subprocess, random, time

# All money contracts from our findings
TARGETS = open("all_money_contracts.txt").read().strip().split("\n")
TARGETS = [t for t in TARGETS if t.startswith("0x") and len(t) == 42][:30]

ECHIDNA_TEMPLATE = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
contract EchidnaRun {
    address constant TARGET = {addr};
    function w() public {{ TARGET.call(abi.encodeWithSignature("withdraw()")); }}
    function k() public {{ TARGET.call(abi.encodeWithSignature("kill()")); }}
    function o() public {{ TARGET.call(abi.encodeWithSignature("transferOwnership(address)", address(this))); }}
    function u() public {{ TARGET.call(abi.encodeWithSignature("upgradeTo(address)", address(this))); }}
    function s() public {{ TARGET.call(abi.encodeWithSignature("sweep()")); }}
    function c() public {{ TARGET.call(abi.encodeWithSignature("claimTokens()")); }}
    function echidna_no_steal() public view returns (bool) {{ return address(this).balance == 0; }}
}}
'''

print(f"Echidna stateful fuzz — {len(TARGETS)} контрактов")
print("=" * 60)

for i, target in enumerate(TARGETS):
    print(f"[{i+1}/{len(TARGETS)}] {target[:14]}...", end=" ")
    
    # Generate test file
    test_code = ECHIDNA_TEMPLATE.replace("{addr}", target)
    with open("/tmp/echidna_test.sol", "w") as f:
        f.write(test_code)
    
    # Run Echidna via Docker
    try:
        result = subprocess.run([
            "docker", "run", "--rm", "-i",
            "trailofbits/echidna",
            "/bin/sh", "-c",
            f"cat > /tmp/test.sol && echidna /tmp/test.sol --test-limit 2000 --contract EchidnaRun 2>&1 | grep -E 'passing|falsified|FAILED|Unique|Total calls'"
        ], input=test_code.encode(), capture_output=True, text=True, timeout=60)
        
        output = result.stdout.strip()
        if "falsified" in output or "FAILED" in output:
            print(f"🚨 VIOLATION!")
            print(f"   {output[:200]}")
            with open("echidna_violations.txt", "a") as f:
                f.write(f"{target} | {output}\n")
        elif "passing" in output:
            print("✅")
        else:
            print(f"⚠️ {output[:80]}")
    except subprocess.TimeoutExpired:
        print("⏰ таймаут")
    except Exception as e:
        print(f"❌ {str(e)[:50]}")
    
    time.sleep(0.5)

print("\nГотово. Результаты в echidna_violations.txt")
