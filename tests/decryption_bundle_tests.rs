use std::process::Command;
use std::path::Path;
use tokio::fs;

#[tokio::test]
async fn test_all_decryption_bundles() {
    // This test walks the tests/decryption_bundles directory and validates each bundle
    let bundles_dir = Path::new("tests/decryption_bundles");
    
    if !bundles_dir.exists() {
        println!("⚠️  No decryption bundles directory found at {}", bundles_dir.display());
        println!("   Create {} and add test bundles to enable automated validation", bundles_dir.display());
        return;
    }

    let mut entries = fs::read_dir(bundles_dir).await.expect("Failed to read bundles directory");
    let mut bundle_count = 0;
    let mut success_count = 0;

    while let Some(entry) = entries.next_entry().await.expect("Failed to read directory entry") {
        let path = entry.path();
        if path.is_dir() {
            bundle_count += 1;
            let bundle_name = path.file_name().unwrap().to_string_lossy();
            
            println!("🔍 Testing bundle: {}", bundle_name);
            
            // Run debug_decrypt as a subprocess
            let output = Command::new("cargo")
                .args(&["run", "--bin", "debug_decrypt", "--", path.to_str().unwrap()])
                .output()
                .expect("Failed to execute debug_decrypt");

            if output.status.success() {
                println!("✅ Bundle {} validated successfully", bundle_name);
                success_count += 1;
            } else {
                println!("❌ Bundle {} validation failed", bundle_name);
                println!("stdout: {}", String::from_utf8_lossy(&output.stdout));
                println!("stderr: {}", String::from_utf8_lossy(&output.stderr));
                
                // Fail the test if any bundle validation fails
                panic!("Bundle validation failed for {}", bundle_name);
            }
        }
    }

    if bundle_count == 0 {
        println!("⚠️  No bundles found in {}", bundles_dir.display());
        println!("   Add test bundles to enable automated validation");
    } else {
        println!("🎉 Validated {}/{} bundles successfully", success_count, bundle_count);
    }
}

#[tokio::test]
async fn test_bundle_structure_validation() {
    // Test that our debug_decrypt tool properly validates bundle structure
    use tempfile::TempDir;

    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let bundle_path = temp_dir.path().join("test_bundle");
    fs::create_dir(&bundle_path).await.expect("Failed to create bundle directory");

    // Test with missing required files
    let output = Command::new("cargo")
        .args(&["run", "--bin", "debug_decrypt", "--", bundle_path.to_str().unwrap()])
        .output()
        .expect("Failed to execute debug_decrypt");

    assert!(!output.status.success(), "Should fail with missing files");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Missing message.bin"), "Should report missing message.bin");
}