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
fn test_comprehensive_stepping() -> Result<()> {
    let binary_path = compile_demo()?;

    let mut target = match Target::launch(binary_path) {
        Ok(t) => t,
        Err(err) if err.to_string().contains("Failed to set TRACESYSGOOD option") => {
            eprintln!("Skipping test: {err}");
            return Ok(());
        }
        Err(err) => return Err(err),
    };

    println!("\n=== Comprehensive Stepping Test ===\n");

    // Set breakpoint on main
    println!("Setting breakpoint on 'main'...");
    let bp = target.create_function_breakpoint("main".to_string(), false)?;
    let bp_id = bp.id();
    target.breakpoints.get_by_id_mut(bp_id).unwrap()
        .enable(&mut target.process, &target.elf)?;

    // Continue to main
    target.process.resume()?;
    let reason = target.process.wait_on_signal()?;
    target.notify_stop(&reason)?;
    assert!(reason.is_breakpoint());

    let entry = target.line_entry_at_pc()?;
    println!("✓ Stopped at {}:{}",
        entry.as_ref().unwrap().file.as_ref().unwrap().path.file_name().unwrap().to_str().unwrap(),
        entry.as_ref().unwrap().line);

    // Remove breakpoint
    if let Some(mut bp) = target.breakpoints.remove_by_id(bp_id) {
        bp.remove_sites(&mut target.process)?;
    }

    // Step over the println
    println!("\nStep over println...");
    let reason = target.step_over()?;
    target.notify_stop(&reason)?;
    assert!(reason.is_step());
    let entry = target.line_entry_at_pc()?.unwrap();
    println!("✓ Now at line {}", entry.line);

    // Step into calculate function
    println!("\nStep into calculate()...");
    let reason = target.step_in()?;
    target.notify_stop(&reason)?;
    assert!(reason.is_step());
    let entry = target.line_entry_at_pc()?.unwrap();
    println!("✓ Inside calculate at line {}", entry.line);

    // Step over add call
    println!("\nStep over add()...");
    let reason = target.step_over()?;
    target.notify_stop(&reason)?;
    assert!(reason.is_step());
    let entry = target.line_entry_at_pc()?.unwrap();
    println!("✓ After add() at line {}", entry.line);

    // Step into multiply
    println!("\nStep into multiply()...");
    let reason = target.step_in()?;
    target.notify_stop(&reason)?;
    assert!(reason.is_step());
    let entry = target.line_entry_at_pc()?.unwrap();
    println!("✓ Inside multiply at line {}", entry.line);

    // Step out of multiply
    println!("\nStep out of multiply()...");
    let reason = target.step_out()?;
    target.notify_stop(&reason)?;
    assert!(reason.is_step());
    let entry = target.line_entry_at_pc()?.unwrap();
    println!("✓ Back in calculate at line {}", entry.line);

    // Continue to completion
    println!("\nContinuing to completion...");
    target.process.resume()?;
    let reason = target.process.wait_on_signal()?;
    assert_eq!(reason.status(), Pstatus::Exited);
    println!("✓ Program exited\n");

    println!("=== All Stepping Operations Successful! ===\n");

    Ok(())
}
