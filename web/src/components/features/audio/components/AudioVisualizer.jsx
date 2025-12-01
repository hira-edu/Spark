import React, { useEffect, useRef } from 'react';
import './AudioVisualizer.css';

/**
 * AudioVisualizer - Visual representation of audio waveform
 */
export const AudioVisualizer = ({ audioData, muted, volume }) => {
  const canvasRef = useRef(null);
  const animationRef = useRef(null);
  const dataRef = useRef(audioData);

  // Update data ref when audioData changes
  useEffect(() => {
    dataRef.current = audioData;
  }, [audioData]);

  // Drawing function
  const draw = () => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    const width = canvas.width;
    const height = canvas.height;

    // Clear canvas
    ctx.fillStyle = 'rgba(26, 26, 46, 0.3)';
    ctx.fillRect(0, 0, width, height);

    // Get audio data
    const data = dataRef.current;

    if (data && data.length > 0) {
      // Draw waveform
      const sliceWidth = width / data.length;
      const amp = muted ? 0 : (volume / 100);

      // Create gradient
      const gradient = ctx.createLinearGradient(0, 0, 0, height);
      gradient.addColorStop(0, '#3b82f6');
      gradient.addColorStop(0.5, '#60a5fa');
      gradient.addColorStop(1, '#3b82f6');

      ctx.strokeStyle = gradient;
      ctx.lineWidth = 2;
      ctx.beginPath();

      let x = 0;
      for (let i = 0; i < data.length; i++) {
        const v = (data[i] / 128.0) * amp;
        const y = (v * height) / 2 + height / 2;

        if (i === 0) {
          ctx.moveTo(x, y);
        } else {
          ctx.lineTo(x, y);
        }

        x += sliceWidth;
      }

      ctx.lineTo(width, height / 2);
      ctx.stroke();

      // Draw bars
      const barCount = 64;
      const barWidth = width / barCount;
      const barSpacing = 2;
      const samplesPerBar = Math.floor(data.length / barCount);

      for (let i = 0; i < barCount; i++) {
        let sum = 0;
        for (let j = 0; j < samplesPerBar; j++) {
          const index = i * samplesPerBar + j;
          if (index < data.length) {
            sum += data[index];
          }
        }
        const average = sum / samplesPerBar / 128.0;
        const barHeight = (average * height * amp) / 2;

        const x = i * barWidth;
        const y = height / 2 - barHeight / 2;

        // Bar gradient
        const barGradient = ctx.createLinearGradient(x, y, x, y + barHeight);
        barGradient.addColorStop(0, '#3b82f6');
        barGradient.addColorStop(1, '#1e40af');

        ctx.fillStyle = barGradient;
        ctx.fillRect(x, y, barWidth - barSpacing, barHeight);
      }
    } else {
      // Draw idle state
      const centerY = height / 2;
      ctx.strokeStyle = 'rgba(59, 130, 246, 0.3)';
      ctx.lineWidth = 2;
      ctx.beginPath();
      ctx.moveTo(0, centerY);
      ctx.lineTo(width, centerY);
      ctx.stroke();
    }

    // Continue animation
    animationRef.current = requestAnimationFrame(draw);
  };

  // Start animation loop
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    // Set canvas size
    const resizeCanvas = () => {
      const container = canvas.parentElement;
      if (container) {
        canvas.width = container.clientWidth;
        canvas.height = container.clientHeight;
      }
    };

    resizeCanvas();
    window.addEventListener('resize', resizeCanvas);

    // Start drawing
    animationRef.current = requestAnimationFrame(draw);

    return () => {
      window.removeEventListener('resize', resizeCanvas);
      if (animationRef.current) {
        cancelAnimationFrame(animationRef.current);
      }
    };
  }, [muted, volume]);

  return (
    <div className="audio-visualizer">
      <canvas ref={canvasRef} className="audio-visualizer-canvas" />
      <div className="audio-visualizer-overlay">
        {muted && (
          <div className="audio-visualizer-muted">MUTED</div>
        )}
      </div>
    </div>
  );
};
