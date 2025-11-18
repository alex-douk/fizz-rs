//! Example: Generate and verify a delegated credential
//!
//! Usage: cargo run --example generate_credential

use fizz_rs::{Certificate, CredentialGenerator};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Delegated Credential Generation Example ===\n");

    // Step 1: Load parent certificate
    println!("1. Loading parent certificate...");
    let cert = Certificate::load_from_files(
        "../sidecar_cert.pem",
        "../sidecar_key.pem"
    )?;

    println!("   ✓ Certificate loaded successfully");
    println!("   Signature schemes: {:?}", cert.signature_schemes());

    // Step 2: Create credential generator
    println!("\n2. Creating credential generator...");
    let generator = match CredentialGenerator::new(cert) {
        Ok(gen) => {
            println!("   ✓ Generator created successfully");
            gen
        }
        Err(e) => {
            println!("   ✗ Failed to create generator: {}", e);
            println!("   Note: The certificate must have delegated credential extensions");
            return Ok(());
        }
    };

    // Step 3: Generate delegated credential
    println!("\n3. Generating delegated credential...");
    let service_name = "example-api-service";
    let valid_for_seconds = 24 * 3600; // 1 day

    let credential = generator.generate(service_name, valid_for_seconds)?;

    println!("   ✓ Credential generated successfully");
    println!("   Service name: {}", credential.service_name());
    println!("   Created at: {}", credential.created_at());
    println!("   Expires at: {}", credential.expires_at());
    println!("   Is expired: {}", credential.is_expired());

    // Step 4: Self-verify the credential
    println!("\n4. Verifying delegated credential...");
    let is_valid = generator.verify(&credential)?;

    if is_valid {
        println!("   ✓ Credential verification PASSED");
    } else {
        println!("   ✗ Credential verification FAILED");
        return Err("Credential verification failed".into());
    }

    // Step 5: Export credential to PEM
    println!("\n5. Exporting credential to PEM format...");
    let pem = credential.to_pem();
    println!("   ✓ Credential exported ({} bytes)", pem.len());
    println!("   First 200 chars:\n   {}",
             pem.chars().take(200).collect::<String>().replace('\n', "\n   "));

    // Step 6: Get public verification info
    println!("\n6. Extracting public verification information...");
    let verification_info = credential.verification_info();

    println!("   Service name: {}", verification_info.service_name);
    println!("   Valid time: {} seconds", verification_info.valid_time);
    println!("   Expected verify scheme: {}", verification_info.expected_verify_scheme);
    println!("   Expires at: {}", verification_info.expires_at);

    // Step 7: Convert verification info to JSON
    println!("\n7. Converting verification info to JSON...");
    let json = verification_info.to_json();
    println!("   ✓ JSON generated:");
    println!("   {}", json);

    println!("\n=== Example completed successfully! ===");

    Ok(())
}
