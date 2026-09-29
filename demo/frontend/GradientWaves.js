/**
 * GradientWaves — Vanilla JS WebGL2 Implementation
 * Based on React Bits GradientWaves (by David Haz)
 * 
 * Raymarched animated wave background with gradient shading,
 * fog, depth perspective, interactive mouse parallax, and film grain.
 */

class GradientWaves {
  constructor(container, options = {}) {
    if (typeof container === 'string') {
      this.container = document.querySelector(container);
    } else {
      this.container = container;
    }

    if (!this.container) {
      console.warn('GradientWaves: container element not found');
      return;
    }

    this.options = {
      horizonColor: options.horizonColor || '#6b8a3c',
      waveColor: options.waveColor || '#d2f83c',
      crestColor: options.crestColor || '#FFFFFF',
      speed: options.speed ?? 0.4,
      amplitude: options.amplitude ?? 2.5,
      waveScale: options.waveScale ?? 0.6,
      waveRatio: options.waveRatio ?? 0.9,
      swell: options.swell ?? 35,
      turbulence: options.turbulence ?? 20,
      tilt: options.tilt ?? 1.11,
      zoom: options.zoom ?? 1,
      height: options.height ?? 5.5,
      fogDepth: options.fogDepth ?? 16,
      detail: options.detail || 'medium',
      brightness: options.brightness ?? 0.82,
      opacity: options.opacity ?? 0.85,
      mouseInteraction: options.mouseInteraction === true,
      parallaxStrength: options.parallaxStrength ?? 0.5,
      grain: options.grain !== false,
      grainIntensity: options.grainIntensity ?? 0.05,
    };

    this._steps = this._getSteps(this.options.detail);
    this._rafId = 0;
    this._isVisible = true;
    this._isDocVisible = !document.hidden;
    this._mouse = [0.5, 0.5];
    this._targetMouse = [0.5, 0.5];
    this._startTime = performance.now();

    this._init();
  }

  _getSteps(detail) {
    if (detail === 'low') return 40.0;
    if (detail === 'high') return 110.0;
    return 70.0; // medium
  }

  _hexToRgb(hex) {
    const match = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
    return match
      ? [parseInt(match[1], 16) / 255, parseInt(match[2], 16) / 255, parseInt(match[3], 16) / 255]
      : [1.0, 1.0, 1.0];
  }

  _init() {
    this.canvas = document.createElement('canvas');
    this.canvas.className = 'gradient-waves-canvas';
    this.canvas.style.position = 'absolute';
    this.canvas.style.top = '0';
    this.canvas.style.left = '0';
    this.canvas.style.width = '100%';
    this.canvas.style.height = '100%';
    this.canvas.style.display = 'block';
    this.canvas.style.pointerEvents = this.options.mouseInteraction ? 'auto' : 'none';

    this.container.appendChild(this.canvas);

    const gl = this.canvas.getContext('webgl2', {
      alpha: true,
      premultipliedAlpha: true,
      antialias: false,
      powerPreference: 'high-performance'
    });

    if (!gl) {
      console.warn('GradientWaves: WebGL2 not supported on this device');
      return;
    }

    this.gl = gl;
    gl.clearColor(0, 0, 0, 0);

    // Build shader program
    const vsSource = `#version 300 es
in vec2 position;
void main() {
  gl_Position = vec4(position, 0.0, 1.0);
}
`;

    const fsSource = `#version 300 es
precision highp float;
uniform vec2 iResolution;
uniform float iTime;
uniform float uSpeed;
uniform float uAmplitude;
uniform float uWaveScale;
uniform float uWaveRatio;
uniform float uSwell;
uniform float uTurbulence;
uniform float uTilt;
uniform float uZoom;
uniform float uHeight;
uniform float uFogDepth;
uniform float uSteps;
uniform float uBrightness;
uniform float uOpacity;
uniform float uGrain;
uniform float uGrainIntensity;
uniform vec2 uMouse;
uniform float uParallax;
uniform bool uEnableMouse;
uniform vec3 uHorizonColor;
uniform vec3 uWaveColor;
uniform vec3 uCrestColor;
out vec4 fragColor;

const float MAX_DIST = 20000.0;

float hash21(vec2 p) {
  vec3 p3 = fract(vec3(p.xyx) * 0.1031);
  p3 += dot(p3, p3.yzx + 33.33);
  return fract((p3.x + p3.y) * p3.z);
}

float plasma(vec3 r, vec2 freq, vec4 tc) {
  float mx = r.x + tc.x;
  mx += uSwell * sin((r.y + mx) / 20.0 + tc.y);
  float my = r.y - tc.z;
  my += uTurbulence * cos(r.x / 23.0 + tc.w);
  return r.z - (sin(mx * freq.x) * uAmplitude + sin(my * freq.y) * uAmplitude + uHeight);
}

float raymarch(vec3 pos, vec3 dir, vec2 freq, vec4 tc) {
  float dist = 0.0;
  for (int i = 0; i < 128; i++) {
    if (float(i) >= uSteps) break;
    float dscene = plasma(pos + dist * dir, freq, tc);
    if (abs(dscene) < 0.1) break;
    dist += 0.9 * dscene;
    if (!(abs(dist) < MAX_DIST)) return MAX_DIST;
  }
  return dist;
}

void main() {
  float T = iTime * uSpeed;
  vec2 freq = vec2(uWaveScale / 7.0, (uWaveScale * uWaveRatio) / 3.0);
  vec4 tc = vec4(T / 0.130, T / 0.810, T / 0.200, T / 0.710);
  float c, s;
  float vfov = (3.14159 / 2.3) / max(uZoom, 0.05);
  vec3 cam = vec3(0.0, 0.0, 30.0);
  
  // Responsive Display Ratio Adaptation:
  // Center coordinates around (0,0) and adaptively normalize across every aspect ratio
  vec2 uv = (gl_FragCoord.xy - 0.5 * iResolution.xy);
  float aspect = iResolution.x / iResolution.y;
  
  float baseDim = iResolution.y;
  if (aspect < 1.0) {
    // Mobile / Portrait: adapt base dimension so wave crests remain lush and panoramic
    baseDim = iResolution.x * 1.35;
  } else if (aspect > 2.0) {
    // Ultrawide / Wide displays: gracefully scale base dimension to prevent horizontal distortion
    baseDim = iResolution.y * (1.0 + (aspect - 2.0) * 0.35);
  }
  uv /= baseDim;
  uv.y *= -1.0;

  vec3 dir = vec3(0.0, 0.0, -1.0);
  float ulen = length(uv);
  // Using atan ensures rays smoothly fan out without ever flipping backwards (max 78 deg):
  float xrot = min(atan(ulen * vfov), 1.36);
  c = cos(xrot); s = sin(xrot);
  dir = mat3(1.0, 0.0, 0.0, 0.0, c, -s, 0.0, s, c) * dir;
  vec2 nuv = ulen > 1e-5 ? uv / ulen : vec2(1.0, 0.0);
  c = nuv.x; s = nuv.y;
  dir = mat3(c, -s, 0.0, s, c, 0.0, 0.0, 0.0, 1.0) * dir;
  c = cos(uTilt); s = sin(uTilt);
  dir = mat3(c, 0.0, s, 0.0, 1.0, 0.0, -s, 0.0, c) * dir;

  if (uEnableMouse) {
    float yaw = (uMouse.x - 0.5) * uParallax * 0.4;
    float pitch = (uMouse.y - 0.5) * uParallax * 0.4;
    c = cos(yaw); s = sin(yaw);
    dir = mat3(c, 0.0, s, 0.0, 1.0, 0.0, -s, 0.0, c) * dir;
    c = cos(pitch); s = sin(pitch);
    dir = mat3(1.0, 0.0, 0.0, 0.0, c, -s, 0.0, s, c) * dir;
  }

  float dist = raymarch(cam, dir, freq, tc);
  vec3 pos = cam + dist * dir;

  float t = clamp(uFogDepth / max(dist, 0.001), 0.0, 1.0);
  vec3 body = mix(uWaveColor, uCrestColor, clamp(pos.z * 0.08 + 0.5, 0.0, 1.0));
  vec3 col = mix(uHorizonColor, body, t);
  col *= uBrightness;
  col = clamp(col, 0.0, 1.0);

  float alpha = clamp(t, 0.0, 1.0) * uOpacity;
  if (uGrain > 0.5) {
    float g = hash21(gl_FragCoord.xy + mod(iTime, 64.0) * 11.0);
    alpha += (g - 0.5) * uGrainIntensity;
  }
  alpha = clamp(alpha, 0.0, 1.0);
  fragColor = vec4(col * alpha, alpha);
}
`;

    const program = this._createProgram(gl, vsSource, fsSource);
    if (!program) return;
    this.program = program;

    // Full-screen triangle geometry
    const positionBuffer = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, positionBuffer);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([
      -1, -1,
       3, -1,
      -1,  3
    ]), gl.STATIC_DRAW);

    const posAttrLoc = gl.getAttribLocation(program, 'position');
    this.vao = gl.createVertexArray();
    gl.bindVertexArray(this.vao);
    gl.enableVertexAttribArray(posAttrLoc);
    gl.vertexAttribPointer(posAttrLoc, 2, gl.FLOAT, false, 0, 0);

    // Cache uniform locations
    gl.useProgram(program);
    this.uniforms = {
      iResolution: gl.getUniformLocation(program, 'iResolution'),
      iTime: gl.getUniformLocation(program, 'iTime'),
      uSpeed: gl.getUniformLocation(program, 'uSpeed'),
      uAmplitude: gl.getUniformLocation(program, 'uAmplitude'),
      uWaveScale: gl.getUniformLocation(program, 'uWaveScale'),
      uWaveRatio: gl.getUniformLocation(program, 'uWaveRatio'),
      uSwell: gl.getUniformLocation(program, 'uSwell'),
      uTurbulence: gl.getUniformLocation(program, 'uTurbulence'),
      uTilt: gl.getUniformLocation(program, 'uTilt'),
      uZoom: gl.getUniformLocation(program, 'uZoom'),
      uHeight: gl.getUniformLocation(program, 'uHeight'),
      uFogDepth: gl.getUniformLocation(program, 'uFogDepth'),
      uSteps: gl.getUniformLocation(program, 'uSteps'),
      uBrightness: gl.getUniformLocation(program, 'uBrightness'),
      uOpacity: gl.getUniformLocation(program, 'uOpacity'),
      uGrain: gl.getUniformLocation(program, 'uGrain'),
      uGrainIntensity: gl.getUniformLocation(program, 'uGrainIntensity'),
      uMouse: gl.getUniformLocation(program, 'uMouse'),
      uParallax: gl.getUniformLocation(program, 'uParallax'),
      uEnableMouse: gl.getUniformLocation(program, 'uEnableMouse'),
      uHorizonColor: gl.getUniformLocation(program, 'uHorizonColor'),
      uWaveColor: gl.getUniformLocation(program, 'uWaveColor'),
      uCrestColor: gl.getUniformLocation(program, 'uCrestColor'),
    };

    // Set static uniforms
    this._updateStaticUniforms();

    // Resize handling
    this._handleResize = () => {
      const rect = this.container.getBoundingClientRect();
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      const w = Math.max(1, Math.floor(rect.width * dpr));
      const h = Math.max(1, Math.floor(rect.height * dpr));

      if (this.canvas.width !== w || this.canvas.height !== h) {
        this.canvas.width = w;
        this.canvas.height = h;
        gl.viewport(0, 0, w, h);
        gl.useProgram(this.program);
        gl.uniform2f(this.uniforms.iResolution, w, h);
      }
    };

    this.resizeObserver = new ResizeObserver(this._handleResize);
    this.resizeObserver.observe(this.container);
    this._handleResize();

    // Mouse parallax tracking
    if (this.options.mouseInteraction) {
      this._onPointerMove = (e) => {
        const rect = this.canvas.getBoundingClientRect();
        this._targetMouse[0] = (e.clientX - rect.left) / rect.width;
        this._targetMouse[1] = 1.0 - (e.clientY - rect.top) / rect.height;
      };

      this._onPointerLeave = () => {
        this._targetMouse[0] = 0.5;
        this._targetMouse[1] = 0.5;
      };

      // Listen on window/container for responsive mouse response
      window.addEventListener('pointermove', this._onPointerMove, { passive: true });
      this.container.addEventListener('pointerleave', this._onPointerLeave, { passive: true });
    }

    // Visibility / Intersection observer to save GPU when off-screen
    this.intersectionObserver = new IntersectionObserver(([entry]) => {
      this._isVisible = entry.isIntersecting;
      if (this._isVisible) {
        this._startAnimation();
      } else {
        this._stopAnimation();
      }
    }, { threshold: 0.05 });
    this.intersectionObserver.observe(this.container);

    this._onVisibilityChange = () => {
      this._isDocVisible = !document.hidden;
      if (this._isDocVisible && this._isVisible) {
        this._startAnimation();
      } else {
        this._stopAnimation();
      }
    };
    document.addEventListener('visibilitychange', this._onVisibilityChange);

    this._startAnimation();
  }

  _updateStaticUniforms() {
    const gl = this.gl;
    gl.useProgram(this.program);

    gl.uniform1f(this.uniforms.uSpeed, this.options.speed);
    gl.uniform1f(this.uniforms.uAmplitude, this.options.amplitude);
    gl.uniform1f(this.uniforms.uWaveScale, this.options.waveScale);
    gl.uniform1f(this.uniforms.uWaveRatio, this.options.waveRatio);
    gl.uniform1f(this.uniforms.uSwell, this.options.swell);
    gl.uniform1f(this.uniforms.uTurbulence, this.options.turbulence);
    gl.uniform1f(this.uniforms.uTilt, this.options.tilt);
    gl.uniform1f(this.uniforms.uZoom, this.options.zoom);
    gl.uniform1f(this.uniforms.uHeight, this.options.height);
    gl.uniform1f(this.uniforms.uFogDepth, this.options.fogDepth);
    gl.uniform1f(this.uniforms.uSteps, this._steps);
    gl.uniform1f(this.uniforms.uBrightness, this.options.brightness);
    gl.uniform1f(this.uniforms.uOpacity, this.options.opacity);
    gl.uniform1f(this.uniforms.uGrain, this.options.grain ? 1.0 : 0.0);
    gl.uniform1f(this.uniforms.uGrainIntensity, this.options.grainIntensity);
    gl.uniform1f(this.uniforms.uParallax, this.options.parallaxStrength);
    gl.uniform1i(this.uniforms.uEnableMouse, this.options.mouseInteraction ? 1 : 0);

    const hc = this._hexToRgb(this.options.horizonColor);
    gl.uniform3f(this.uniforms.uHorizonColor, hc[0], hc[1], hc[2]);

    const wc = this._hexToRgb(this.options.waveColor);
    gl.uniform3f(this.uniforms.uWaveColor, wc[0], wc[1], wc[2]);

    const cc = this._hexToRgb(this.options.crestColor);
    gl.uniform3f(this.uniforms.uCrestColor, cc[0], cc[1], cc[2]);
  }

  _createProgram(gl, vsSource, fsSource) {
    const vs = gl.createShader(gl.VERTEX_SHADER);
    gl.shaderSource(vs, vsSource);
    gl.compileShader(vs);
    if (!gl.getShaderParameter(vs, gl.COMPILE_STATUS)) {
      console.error('GradientWaves VS Error:', gl.getShaderInfoLog(vs));
      return null;
    }

    const fs = gl.createShader(gl.FRAGMENT_SHADER);
    gl.shaderSource(fs, fsSource);
    gl.compileShader(fs);
    if (!gl.getShaderParameter(fs, gl.COMPILE_STATUS)) {
      console.error('GradientWaves FS Error:', gl.getShaderInfoLog(fs));
      return null;
    }

    const prog = gl.createProgram();
    gl.attachShader(prog, vs);
    gl.attachShader(prog, fs);
    gl.linkProgram(prog);
    if (!gl.getProgramParameter(prog, gl.LINK_STATUS)) {
      console.error('GradientWaves Link Error:', gl.getProgramInfoLog(prog));
      return null;
    }

    gl.deleteShader(vs);
    gl.deleteShader(fs);
    return prog;
  }

  _startAnimation() {
    if (this._rafId !== 0) return;

    const render = (now) => {
      const gl = this.gl;
      if (!gl || !this.program) return;

      const elapsed = (now - this._startTime) * 0.001;

      // Smooth mouse lerp
      this._mouse[0] += 0.05 * (this._targetMouse[0] - this._mouse[0]);
      this._mouse[1] += 0.05 * (this._targetMouse[1] - this._mouse[1]);

      gl.useProgram(this.program);
      gl.uniform1f(this.uniforms.iTime, elapsed);
      gl.uniform2f(this.uniforms.uMouse, this._mouse[0], this._mouse[1]);

      gl.bindVertexArray(this.vao);
      gl.drawArrays(gl.TRIANGLES, 0, 3);

      this._rafId = requestAnimationFrame(render);
    };

    this._rafId = requestAnimationFrame(render);
  }

  _stopAnimation() {
    if (this._rafId !== 0) {
      cancelAnimationFrame(this._rafId);
      this._rafId = 0;
    }
  }

  destroy() {
    this._stopAnimation();
    if (this.resizeObserver) this.resizeObserver.disconnect();
    if (this.intersectionObserver) this.intersectionObserver.disconnect();
    document.removeEventListener('visibilitychange', this._onVisibilityChange);
    if (this._onPointerMove) window.removeEventListener('pointermove', this._onPointerMove);

    if (this.gl) {
      const ext = this.gl.getExtension('WEBGL_lose_context');
      if (ext) ext.loseContext();
    }

    if (this.canvas && this.canvas.parentNode) {
      this.canvas.parentNode.removeChild(this.canvas);
    }
  }
}

// Attach to window
window.GradientWaves = GradientWaves;
