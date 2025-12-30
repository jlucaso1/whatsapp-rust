//! Waveform generation for WhatsApp PTT voice messages
//!
//! WhatsApp uses a 64-byte waveform visualization where each byte
//! represents amplitude values in the range 0-100.

/// Number of samples in the waveform (WhatsApp standard)
pub const WAVEFORM_SAMPLES: usize = 64;

/// Maximum waveform amplitude value
const MAX_AMPLITUDE: u8 = 100;

/// Generate a waveform from audio samples
///
/// Takes raw audio samples (f32, -1.0 to 1.0 range) and produces
/// a 64-byte waveform suitable for WhatsApp PTT messages.
///
/// The algorithm:
/// 1. Divides samples into 64 chunks
/// 2. Computes RMS (root mean square) for each chunk
/// 3. Normalizes to 0-100 range
pub fn generate_waveform(samples: &[f32]) -> Vec<u8> {
    if samples.is_empty() {
        return vec![0u8; WAVEFORM_SAMPLES];
    }

    let chunk_size = samples.len() / WAVEFORM_SAMPLES;
    if chunk_size == 0 {
        // Very short audio - just take absolute values and pad
        // Clamp to MAX_AMPLITUDE to handle samples outside -1.0..1.0 range
        let mut waveform: Vec<u8> = samples
            .iter()
            .map(|s| (s.abs() * MAX_AMPLITUDE as f32).min(MAX_AMPLITUDE as f32) as u8)
            .collect();
        waveform.resize(WAVEFORM_SAMPLES, 0);
        return waveform;
    }

    // Calculate RMS for each chunk
    let mut rms_values: Vec<f32> = Vec::with_capacity(WAVEFORM_SAMPLES);
    for chunk in samples.chunks(chunk_size).take(WAVEFORM_SAMPLES) {
        let sum_squares: f32 = chunk.iter().map(|s| s * s).sum();
        let rms = (sum_squares / chunk.len() as f32).sqrt();
        rms_values.push(rms);
    }

    // Find max RMS for normalization
    let max_rms = rms_values.iter().copied().fold(f32::MIN, f32::max);
    if max_rms < f32::EPSILON {
        return vec![0u8; WAVEFORM_SAMPLES];
    }

    // Normalize to 0-100 range
    let mut waveform: Vec<u8> = rms_values
        .iter()
        .map(|rms| ((rms / max_rms) * MAX_AMPLITUDE as f32) as u8)
        .collect();

    // Ensure exactly 64 samples
    waveform.resize(WAVEFORM_SAMPLES, 0);
    waveform
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_waveform_length() {
        let samples = vec![0.5f32; 1000];
        let waveform = generate_waveform(&samples);
        assert_eq!(waveform.len(), WAVEFORM_SAMPLES);
    }

    #[test]
    fn test_waveform_range() {
        let samples: Vec<f32> = (0..10000).map(|i| (i as f32 / 100.0).sin()).collect();
        let waveform = generate_waveform(&samples);
        for &val in &waveform {
            assert!(val <= MAX_AMPLITUDE);
        }
    }

    #[test]
    fn test_empty_samples() {
        let waveform = generate_waveform(&[]);
        assert_eq!(waveform.len(), WAVEFORM_SAMPLES);
        assert!(waveform.iter().all(|&v| v == 0));
    }

    #[test]
    fn test_silent_audio() {
        let samples = vec![0.0f32; 10000];
        let waveform = generate_waveform(&samples);
        assert!(waveform.iter().all(|&v| v == 0));
    }
}
