/**
 * useWebGLRenderer - WebGL-accelerated remote desktop renderer
 *
 * Based on Apache Guacamole's WebGL rendering approach.
 * Provides GPU-accelerated image compositing for remote desktop frames.
 *
 * Benefits over Canvas 2D:
 * - GPU texture uploads (faster than putImageData)
 * - YUV→RGB conversion on GPU (for video codecs)
 * - Bilinear interpolation for scaling
 * - Lower CPU usage for high-resolution displays
 *
 * Fallback: Automatically falls back to Canvas 2D if WebGL unavailable
 *
 * Reference: Apache Guacamole client-js/src/Display.js
 */
import { useRef, useCallback, useEffect, useState } from 'react';

// Vertex shader - simple pass-through for 2D rendering
const VERTEX_SHADER_SOURCE = `
  attribute vec2 a_position;
  attribute vec2 a_texCoord;
  varying vec2 v_texCoord;
  uniform vec2 u_resolution;

  void main() {
    // Convert from pixels to clip space (-1 to +1)
    vec2 clipSpace = ((a_position / u_resolution) * 2.0) - 1.0;
    gl_Position = vec4(clipSpace * vec2(1, -1), 0, 1);
    v_texCoord = a_texCoord;
  }
`;

// Fragment shader - texture sampling with optional YUV conversion
const FRAGMENT_SHADER_SOURCE = `
  precision mediump float;
  varying vec2 v_texCoord;
  uniform sampler2D u_texture;
  uniform int u_colorSpace; // 0=RGBA, 1=YUV420

  // YUV to RGB conversion matrix (BT.601)
  const mat3 yuv2rgb = mat3(
    1.0,     1.0,      1.0,
    0.0,    -0.344136, 1.772,
    1.402,  -0.714136, 0.0
  );

  void main() {
    vec4 texColor = texture2D(u_texture, v_texCoord);

    if (u_colorSpace == 1) {
      // YUV conversion (for VP8/VP9/H.264 decoded frames)
      vec3 yuv = texColor.rgb - vec3(0.0, 0.5, 0.5);
      vec3 rgb = yuv2rgb * yuv;
      gl_FragColor = vec4(clamp(rgb, 0.0, 1.0), 1.0);
    } else {
      // Direct RGBA passthrough
      gl_FragColor = texColor;
    }
  }
`;

/**
 * Compiles a shader from source
 */
function compileShader(gl, type, source) {
  const shader = gl.createShader(type);
  gl.shaderSource(shader, source);
  gl.compileShader(shader);

  if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) {
    console.error('Shader compile error:', gl.getShaderInfoLog(shader));
    gl.deleteShader(shader);
    return null;
  }
  return shader;
}

/**
 * Creates a WebGL program from vertex and fragment shaders
 */
function createProgram(gl, vertexShader, fragmentShader) {
  const program = gl.createProgram();
  gl.attachShader(program, vertexShader);
  gl.attachShader(program, fragmentShader);
  gl.linkProgram(program);

  if (!gl.getProgramParameter(program, gl.LINK_STATUS)) {
    console.error('Program link error:', gl.getProgramInfoLog(program));
    gl.deleteProgram(program);
    return null;
  }
  return program;
}

/**
 * Block texture cache for efficient re-uploads
 */
class TextureCache {
  constructor(gl, maxTextures = 256) {
    this.gl = gl;
    this.maxTextures = maxTextures;
    this.cache = new Map(); // posKey -> { texture, version }
    this.lru = []; // Least recently used queue
  }

  getOrCreate(posKey, width, height) {
    const gl = this.gl;

    if (this.cache.has(posKey)) {
      // Move to end of LRU
      this.lru = this.lru.filter(k => k !== posKey);
      this.lru.push(posKey);
      return this.cache.get(posKey);
    }

    // Evict oldest if at capacity
    if (this.cache.size >= this.maxTextures && this.lru.length > 0) {
      const oldest = this.lru.shift();
      const entry = this.cache.get(oldest);
      if (entry) {
        gl.deleteTexture(entry.texture);
        this.cache.delete(oldest);
      }
    }

    // Create new texture
    const texture = gl.createTexture();
    gl.bindTexture(gl.TEXTURE_2D, texture);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR);

    // Allocate texture storage
    gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, width, height, 0, gl.RGBA, gl.UNSIGNED_BYTE, null);

    const entry = { texture, width, height, version: 0 };
    this.cache.set(posKey, entry);
    this.lru.push(posKey);

    return entry;
  }

  update(posKey, width, height, data, version) {
    const gl = this.gl;
    const entry = this.getOrCreate(posKey, width, height);

    // Skip if stale
    if (version < entry.version) {
      return false;
    }
    entry.version = version;

    // Resize if needed
    if (entry.width !== width || entry.height !== height) {
      gl.bindTexture(gl.TEXTURE_2D, entry.texture);
      gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, width, height, 0, gl.RGBA, gl.UNSIGNED_BYTE, null);
      entry.width = width;
      entry.height = height;
    }

    // Upload texture data
    gl.bindTexture(gl.TEXTURE_2D, entry.texture);
    gl.texSubImage2D(gl.TEXTURE_2D, 0, 0, 0, width, height, gl.RGBA, gl.UNSIGNED_BYTE, data);

    return true;
  }

  clear() {
    const gl = this.gl;
    for (const entry of this.cache.values()) {
      gl.deleteTexture(entry.texture);
    }
    this.cache.clear();
    this.lru = [];
  }
}

/**
 * useWebGLRenderer hook
 *
 * @param {React.RefObject} canvasRef - Reference to canvas element
 * @param {Object} options - Renderer options
 * @returns {Object} Renderer interface
 */
export function useWebGLRenderer(canvasRef, options = {}) {
  const {
    preferWebGL = true,
    maxTextureCache = 256,
  } = options;

  const [isWebGL, setIsWebGL] = useState(false);
  const glRef = useRef(null);
  const programRef = useRef(null);
  const textureCacheRef = useRef(null);
  const bufferRef = useRef(null);
  const locationsRef = useRef(null);
  const ctx2DRef = useRef(null);
  const initRef = useRef(false);

  // Statistics
  const statsRef = useRef({
    rendered: 0,
    failed: 0,
    stale: 0,
    webglDrawCalls: 0,
    canvas2dCalls: 0,
  });

  /**
   * Initialize WebGL context and shaders
   */
  const initWebGL = useCallback(() => {
    const canvas = canvasRef.current;
    if (!canvas || initRef.current) return false;

    // Try WebGL2 first, then WebGL1
    let gl = canvas.getContext('webgl2', { alpha: false, antialias: false, preserveDrawingBuffer: true });
    if (!gl) {
      gl = canvas.getContext('webgl', { alpha: false, antialias: false, preserveDrawingBuffer: true });
    }

    if (!gl) {
      console.warn('[WebGL] Not available, falling back to Canvas 2D');
      ctx2DRef.current = canvas.getContext('2d', { alpha: false });
      initRef.current = true;
      return false;
    }

    // Compile shaders
    const vertexShader = compileShader(gl, gl.VERTEX_SHADER, VERTEX_SHADER_SOURCE);
    const fragmentShader = compileShader(gl, gl.FRAGMENT_SHADER, FRAGMENT_SHADER_SOURCE);

    if (!vertexShader || !fragmentShader) {
      console.warn('[WebGL] Shader compilation failed, falling back to Canvas 2D');
      ctx2DRef.current = canvas.getContext('2d', { alpha: false });
      initRef.current = true;
      return false;
    }

    const program = createProgram(gl, vertexShader, fragmentShader);
    if (!program) {
      console.warn('[WebGL] Program creation failed, falling back to Canvas 2D');
      ctx2DRef.current = canvas.getContext('2d', { alpha: false });
      initRef.current = true;
      return false;
    }

    // Get attribute/uniform locations
    const locations = {
      position: gl.getAttribLocation(program, 'a_position'),
      texCoord: gl.getAttribLocation(program, 'a_texCoord'),
      resolution: gl.getUniformLocation(program, 'u_resolution'),
      texture: gl.getUniformLocation(program, 'u_texture'),
      colorSpace: gl.getUniformLocation(program, 'u_colorSpace'),
    };

    // Create vertex buffer
    const positionBuffer = gl.createBuffer();
    const texCoordBuffer = gl.createBuffer();

    // Setup texture coordinates (static)
    gl.bindBuffer(gl.ARRAY_BUFFER, texCoordBuffer);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([
      0.0, 0.0,
      1.0, 0.0,
      0.0, 1.0,
      0.0, 1.0,
      1.0, 0.0,
      1.0, 1.0,
    ]), gl.STATIC_DRAW);

    // Store references
    glRef.current = gl;
    programRef.current = program;
    locationsRef.current = locations;
    bufferRef.current = { position: positionBuffer, texCoord: texCoordBuffer };
    textureCacheRef.current = new TextureCache(gl, maxTextureCache);

    // Enable blending for transparency
    gl.enable(gl.BLEND);
    gl.blendFunc(gl.SRC_ALPHA, gl.ONE_MINUS_SRC_ALPHA);

    console.info('[WebGL] Renderer initialized successfully');
    setIsWebGL(true);
    initRef.current = true;

    return true;
  }, [canvasRef, maxTextureCache]);

  /**
   * Initialize renderer (WebGL or Canvas 2D)
   */
  const init = useCallback(() => {
    if (initRef.current) return;

    if (preferWebGL) {
      initWebGL();
    } else {
      const canvas = canvasRef.current;
      if (canvas) {
        ctx2DRef.current = canvas.getContext('2d', { alpha: false });
        initRef.current = true;
      }
    }
  }, [preferWebGL, initWebGL, canvasRef]);

  /**
   * Render a block using WebGL
   */
  const renderBlockWebGL = useCallback((gl, x, y, width, height, imageData, version) => {
    const program = programRef.current;
    const locations = locationsRef.current;
    const buffers = bufferRef.current;
    const textureCache = textureCacheRef.current;
    const canvas = canvasRef.current;

    if (!program || !locations || !buffers || !textureCache || !canvas) return false;

    const posKey = `${x},${y},${width},${height}`;

    // Update texture (handles version checking)
    if (!textureCache.update(posKey, width, height, imageData, version)) {
      statsRef.current.stale++;
      return false;
    }

    gl.useProgram(program);

    // Set resolution uniform
    gl.uniform2f(locations.resolution, canvas.width, canvas.height);
    gl.uniform1i(locations.colorSpace, 0); // RGBA mode

    // Setup position vertices for this block
    const x2 = x + width;
    const y2 = y + height;
    gl.bindBuffer(gl.ARRAY_BUFFER, buffers.position);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([
      x, y,
      x2, y,
      x, y2,
      x, y2,
      x2, y,
      x2, y2,
    ]), gl.DYNAMIC_DRAW);

    // Enable attributes
    gl.enableVertexAttribArray(locations.position);
    gl.vertexAttribPointer(locations.position, 2, gl.FLOAT, false, 0, 0);

    gl.bindBuffer(gl.ARRAY_BUFFER, buffers.texCoord);
    gl.enableVertexAttribArray(locations.texCoord);
    gl.vertexAttribPointer(locations.texCoord, 2, gl.FLOAT, false, 0, 0);

    // Bind texture and draw
    const entry = textureCache.cache.get(posKey);
    gl.activeTexture(gl.TEXTURE0);
    gl.bindTexture(gl.TEXTURE_2D, entry.texture);
    gl.uniform1i(locations.texture, 0);

    gl.drawArrays(gl.TRIANGLES, 0, 6);

    statsRef.current.webglDrawCalls++;
    statsRef.current.rendered++;

    return true;
  }, [canvasRef]);

  /**
   * Render a block using Canvas 2D (fallback)
   */
  const renderBlockCanvas2D = useCallback((ctx, x, y, width, height, imageData) => {
    try {
      const imgData = new ImageData(new Uint8ClampedArray(imageData), width, height);
      ctx.putImageData(imgData, x, y);
      statsRef.current.canvas2dCalls++;
      statsRef.current.rendered++;
      return true;
    } catch (err) {
      console.error('[Canvas2D] Render failed:', err);
      statsRef.current.failed++;
      return false;
    }
  }, []);

  /**
   * Render a raw RGBA block
   */
  const renderBlock = useCallback((x, y, width, height, data, version = 0) => {
    const gl = glRef.current;
    const ctx = ctx2DRef.current;

    if (gl && isWebGL) {
      return renderBlockWebGL(gl, x, y, width, height, new Uint8Array(data), version);
    } else if (ctx) {
      return renderBlockCanvas2D(ctx, x, y, width, height, data);
    }

    statsRef.current.failed++;
    return false;
  }, [isWebGL, renderBlockWebGL, renderBlockCanvas2D]);

  /**
   * Render a compressed image (JPEG/PNG/WebP)
   * Uses createImageBitmap for async decode, then uploads to WebGL
   */
  const renderCompressedBlock = useCallback(async (x, y, width, height, data, version = 0) => {
    const gl = glRef.current;
    const ctx = ctx2DRef.current;
    const canvas = canvasRef.current;

    try {
      const bitmap = await createImageBitmap(new Blob([data]), {
        premultiplyAlpha: 'none',
      });

      if (gl && isWebGL) {
        // For WebGL: extract pixels from bitmap using temp canvas
        const tempCanvas = document.createElement('canvas');
        tempCanvas.width = bitmap.width;
        tempCanvas.height = bitmap.height;
        const tempCtx = tempCanvas.getContext('2d');
        tempCtx.drawImage(bitmap, 0, 0);
        const imageData = tempCtx.getImageData(0, 0, bitmap.width, bitmap.height);
        bitmap.close();

        return renderBlockWebGL(gl, x, y, width, height, imageData.data, version);
      } else if (ctx) {
        ctx.drawImage(bitmap, x, y, width, height);
        bitmap.close();
        statsRef.current.canvas2dCalls++;
        statsRef.current.rendered++;
        return true;
      }
    } catch (err) {
      console.error('[Renderer] Compressed block failed:', err);
      statsRef.current.failed++;
      return false;
    }

    statsRef.current.failed++;
    return false;
  }, [isWebGL, renderBlockWebGL, canvasRef]);

  /**
   * Set canvas size and update WebGL viewport
   */
  const setSize = useCallback((width, height) => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    canvas.width = width;
    canvas.height = height;

    const gl = glRef.current;
    if (gl) {
      gl.viewport(0, 0, width, height);
    }
  }, [canvasRef]);

  /**
   * Clear the canvas
   */
  const clear = useCallback(() => {
    const gl = glRef.current;
    const ctx = ctx2DRef.current;
    const canvas = canvasRef.current;

    if (gl) {
      gl.clearColor(0, 0, 0, 1);
      gl.clear(gl.COLOR_BUFFER_BIT);
    } else if (ctx && canvas) {
      ctx.fillStyle = '#000';
      ctx.fillRect(0, 0, canvas.width, canvas.height);
    }

    // Clear texture cache
    if (textureCacheRef.current) {
      textureCacheRef.current.clear();
    }
  }, [canvasRef]);

  /**
   * Get renderer statistics
   */
  const getStats = useCallback(() => {
    return { ...statsRef.current };
  }, []);

  /**
   * Reset statistics
   */
  const resetStats = useCallback(() => {
    statsRef.current = {
      rendered: 0,
      failed: 0,
      stale: 0,
      webglDrawCalls: 0,
      canvas2dCalls: 0,
    };
  }, []);

  /**
   * Cleanup on unmount
   */
  useEffect(() => {
    return () => {
      if (textureCacheRef.current) {
        textureCacheRef.current.clear();
      }
      if (glRef.current && programRef.current) {
        glRef.current.deleteProgram(programRef.current);
      }
    };
  }, []);

  return {
    init,
    renderBlock,
    renderCompressedBlock,
    setSize,
    clear,
    isWebGL,
    getStats,
    resetStats,
  };
}

export default useWebGLRenderer;
