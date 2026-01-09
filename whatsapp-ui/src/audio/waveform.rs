//! Waveform generation for WhatsApp PTT voice messages.

pub const WAVEFORM_SAMPLES: usize = 64;
const MAX_AMPLITUDE: u8 = 100;

/// Generate a 64-byte waveform from audio samples using RMS.
pub fn generate_waveform(samples: &[f32]) -> Vec<u8> {
    if samples.is_empty() {
        return vec![0u8; WAVEFORM_SAMPLES];
    }

    let chunk_size = samples.len() / WAVEFORM_SAMPLES;
    if chunk_size == 0 {
        let mut waveform: Vec<u8> = samples
            .iter()
            .map(|s| (s.abs() * MAX_AMPLITUDE as f32).min(MAX_AMPLITUDE as f32) as u8)
            .collect();
        waveform.resize(WAVEFORM_SAMPLES, 0);
        return waveform;
    }

    let rms_values: Vec<f32> = samples
        .chunks(chunk_size)
        .take(WAVEFORM_SAMPLES)
        .map(|chunk| {
            let sum_squares: f32 = chunk.iter().map(|s| s * s).sum();
            (sum_squares / chunk.len() as f32).sqrt()
        })
        .collect();

    let max_rms = rms_values.iter().copied().fold(f32::MIN, f32::max);
    if max_rms < f32::EPSILON {
        return vec![0u8; WAVEFORM_SAMPLES];
    }

    let mut waveform: Vec<u8> = rms_values
        .iter()
        .map(|rms| ((rms / max_rms) * MAX_AMPLITUDE as f32) as u8)
        .collect();
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
