use std::path::PathBuf;
use std::process::Command;
use std::ffi::OsStr;
use anyhow::Result;
use rdb::target::Target;
use rdb::process::Pstatus;

fn compile_demo() -> Result<PathBuf> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let source_path = manifest_dir.join("test_programs/demo.rs");
    let out_dir = manifest_dir.join("target/test_bins");
    std::fs::create_dir_all(&out_dir)?;
    let output_path = out_dir.join("demo");

    let status = Command::new("rustc")
        .current_dir(&manifest_dir)
        .args([
            OsStr::new("-g"),
            OsStr::new("-C"),
            OsStr::new("opt-level=0"),
            source_path.as_os_str(),
            OsStr::new("-o"),
            output_path.as_os_str(),
        ])
        .status()?;

    if !status.success() {
        anyhow::bail!("rustc failed");
    }

    Ok(output_path)
}

#[test]
fn test_debugger_demo() -> Result<()> {
    let binary_path = compile_demo()?;

    let mut target = match Target::launch(binary_path) {
        Ok(t) => t,
        Err(err) if err.to_string().contains("Failed to set TRACESYSGOOD option") => {
            eprintln!("Skipping test: {err}");
            return Ok(());
        }
        Err(err) => return Err(err),
    };

    println!("\n=== Testing Debugger with Demo Program ===\n");

    // Test 1: Set breakpoint on 'calculate' function
    println!("1. Setting breakpoint on 'calculate' function...");
    let bp = target.create_function_breakpoint("calculate".to_string(), false)?;
    let bp_id = bp.id();
    target.breakpoints.get_by_id_mut(bp_id).unwrap()
        .enable(&mut target.process, &target.elf)?;
    println!("   ✓ Breakpoint set at function 'calculate'");

    // Test 2: Continue until breakpoint
    println!("\n2. Continuing until breakpoint...");
    target.process.resume()?;
    let reason = target.process.wait_on_signal()?;
    target.notify_stop(&reason)?;
    assert!(reason.is_breakpoint(), "Expected to hit breakpoint");

    let entry = target.line_entry_at_pc()?.expect("Should have line info");
    println!("   ✓ Hit breakpoint at {}:{}",
        entry.file.as_ref().unwrap().path.display(), entry.line);

    // Test 3: Step into add function
    println!("\n3. Stepping into code...");
    let reason = target.step_in()?;
    target.notify_stop(&reason)?;
    assert!(reason.is_step(), "Expected step to succeed");

    let entry = target.line_entry_at_pc()?.expect("Should have line info");
    println!("   ✓ Stepped to {}:{}",
        entry.file.as_ref().unwrap().path.display(), entry.line);

    // Test 4: Step over next line
    println!("\n4. Stepping over next line...");
    let reason = target.step_over()?;
    target.notify_stop(&reason)?;
    assert!(reason.is_step(), "Expected step to succeed");

    let entry = target.line_entry_at_pc()?.expect("Should have line info");
    println!("   ✓ Stepped to {}:{}",
        entry.file.as_ref().unwrap().path.display(), entry.line);

    // Test 5: Continue to completion
    println!("\n5. Continuing to program completion...");
    target.process.resume()?;
    let reason = target.process.wait_on_signal()?;
    assert_eq!(reason.status(), Pstatus::Exited, "Expected program to exit");
    println!("   ✓ Program exited successfully");

    println!("\n=== All Tests Passed! ===\n");

    Ok(())
}
