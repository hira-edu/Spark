import React, { useEffect, useRef, forwardRef, useImperativeHandle, useCallback } from 'react';
import { Terminal } from 'xterm';
import { FitAddon } from 'xterm-addon-fit';
import { WebLinksAddon } from 'xterm-addon-web-links';
import debounce from 'lodash/debounce';
import 'xterm/css/xterm.css';
import './Terminal.css';

// Write chunk size tuned to keep the xterm.js WriteBuffer below its 50MB safety watermark.
// This enforces application-level flow control instead of letting writes accumulate unbounded.
const WRITE_CHUNK_SIZE = 16 * 1024; // 16KB chunks balance throughput and GC pressure

// Theme definitions
const THEMES = {
  dark: {
    background: '#1a1a1a',
    foreground: '#f0f0f0',
    cursor: '#f0f0f0',
    cursorAccent: '#1a1a1a',
    selectionBackground: 'rgba(255, 255, 255, 0.3)',
    black: '#1a1a1a',
    red: '#ff5f56',
    green: '#27c93f',
    yellow: '#ffbd2e',
    blue: '#4a9eff',
    magenta: '#c792ea',
    cyan: '#89ddff',
    white: '#d0d0d0',
    brightBlack: '#666666',
    brightRed: '#ff6b6b',
    brightGreen: '#69ff94',
    brightYellow: '#ffffa5',
    brightBlue: '#6cb6ff',
    brightMagenta: '#ff92df',
    brightCyan: '#a5fffe',
    brightWhite: '#ffffff',
  },
  light: {
    background: '#ffffff',
    foreground: '#1a1a1a',
    cursor: '#1a1a1a',
    cursorAccent: '#ffffff',
    selectionBackground: 'rgba(0, 0, 0, 0.2)',
    black: '#1a1a1a',
    red: '#c91b00',
    green: '#00c200',
    yellow: '#c7c400',
    blue: '#0225c7',
    magenta: '#ca30c7',
    cyan: '#00c5c7',
    white: '#c7c7c7',
    brightBlack: '#686868',
    brightRed: '#ff6e67',
    brightGreen: '#5ffa68',
    brightYellow: '#fffc67',
    brightBlue: '#6871ff',
    brightMagenta: '#ff77ff',
    brightCyan: '#60fdff',
    brightWhite: '#ffffff',
  },
  monokai: {
    background: '#272822',
    foreground: '#f8f8f2',
    cursor: '#f8f8f2',
    cursorAccent: '#272822',
    selectionBackground: 'rgba(255, 255, 255, 0.2)',
    black: '#272822',
    red: '#f92672',
    green: '#a6e22e',
    yellow: '#e6db74',
    blue: '#66d9ef',
    magenta: '#ae81ff',
    cyan: '#a1efe4',
    white: '#f8f8f2',
    brightBlack: '#75715e',
    brightRed: '#f92672',
    brightGreen: '#a6e22e',
    brightYellow: '#e6db74',
    brightBlue: '#66d9ef',
    brightMagenta: '#ae81ff',
    brightCyan: '#a1efe4',
    brightWhite: '#f9f8f5',
  },
  dracula: {
    background: '#282a36',
    foreground: '#f8f8f2',
    cursor: '#f8f8f2',
    cursorAccent: '#282a36',
    selectionBackground: 'rgba(255, 255, 255, 0.2)',
    black: '#21222c',
    red: '#ff5555',
    green: '#50fa7b',
    yellow: '#f1fa8c',
    blue: '#bd93f9',
    magenta: '#ff79c6',
    cyan: '#8be9fd',
    white: '#f8f8f2',
    brightBlack: '#6272a4',
    brightRed: '#ff6e6e',
    brightGreen: '#69ff94',
    brightYellow: '#ffffa5',
    brightBlue: '#d6acff',
    brightMagenta: '#ff92df',
    brightCyan: '#a4ffff',
    brightWhite: '#ffffff',
  },
  retro: {
    background: '#0a0a0a',
    foreground: '#00ff00',
    cursor: '#00ff00',
    cursorAccent: '#0a0a0a',
    selectionBackground: 'rgba(0, 255, 0, 0.2)',
    black: '#0a0a0a',
    red: '#ff0000',
    green: '#00ff00',
    yellow: '#ffff00',
    blue: '#0000ff',
    magenta: '#ff00ff',
    cyan: '#00ffff',
    white: '#00ff00',
    brightBlack: '#005500',
    brightRed: '#ff5555',
    brightGreen: '#55ff55',
    brightYellow: '#ffff55',
    brightBlue: '#5555ff',
    brightMagenta: '#ff55ff',
    brightCyan: '#55ffff',
    brightWhite: '#ffffff',
  },
};

/**
 * XTermWrapper - Wrapper component for xterm.js
 */
const XTermWrapper = forwardRef(({
  theme = 'dark',
  fontSize = 16,
  onData,
  onResize,
}, ref) => {
  const containerRef = useRef(null);
  const termRef = useRef(null);
  const fitAddonRef = useRef(null);
  const dataListenerRef = useRef(null);
  const writeQueueRef = useRef([]);
  const isWritingRef = useRef(false);
  const pendingBytesRef = useRef(0);

  const flushWriteQueue = useCallback(() => {
    const term = termRef.current;
    if (!term || isWritingRef.current) {
      return;
    }
    const chunk = writeQueueRef.current.shift();
    if (typeof chunk !== 'string' || chunk.length === 0) {
      return;
    }

    isWritingRef.current = true;
    pendingBytesRef.current = Math.max(0, pendingBytesRef.current - chunk.length);
    term.write(chunk, () => {
      isWritingRef.current = false;
      flushWriteQueue();
    });
  }, []);

  const enqueueWrite = useCallback((data) => {
    if (!data) {
      return;
    }
    const normalized = typeof data === 'string' ? data : String(data);
    for (let offset = 0; offset < normalized.length; offset += WRITE_CHUNK_SIZE) {
      const chunk = normalized.slice(offset, offset + WRITE_CHUNK_SIZE);
      if (chunk.length > 0) {
        writeQueueRef.current.push(chunk);
        pendingBytesRef.current += chunk.length;
      }
    }
    if (!isWritingRef.current) {
      flushWriteQueue();
    }
  }, [flushWriteQueue]);

  // Expose terminal methods to parent
  useImperativeHandle(ref, () => ({
    write: (data) => enqueueWrite(data),
    clear: () => {
      writeQueueRef.current = [];
      pendingBytesRef.current = 0;
      isWritingRef.current = false;
      termRef.current?.clear();
    },
    focus: () => termRef.current?.focus(),
    fit: () => fitAddonRef.current?.fit(),
    getTerminal: () => termRef.current,
  }), [enqueueWrite]);

  // Initialize terminal
  useEffect(() => {
    if (!containerRef.current) return;

    const term = new Terminal({
      convertEol: true,
      allowProposedApi: true,
      allowTransparency: false,
      cursorBlink: true,
      cursorStyle: 'block',
      fontFamily: 'Hack, Menlo, Monaco, "Courier New", monospace',
      fontSize,
      theme: THEMES[theme] || THEMES.dark,
      scrollback: 10000,
      logLevel: 'off',
    });

    const fitAddon = new FitAddon();
    const webLinksAddon = new WebLinksAddon();

    term.loadAddon(fitAddon);
    term.loadAddon(webLinksAddon);
    term.open(containerRef.current);

    // Initial fit
    fitAddon.fit();

    // Store refs
    termRef.current = term;
    fitAddonRef.current = fitAddon;

    // Handle data from terminal
    dataListenerRef.current = term.onData((data) => {
      if (onData) {
        onData(data);
      }
    });

    // Handle resize
    const handleResize = debounce(() => {
      fitAddon.fit();
      if (onResize && term) {
        onResize({ cols: term.cols, rows: term.rows });
      }
    }, 100);

    window.addEventListener('resize', handleResize);
    term.focus();

    // Initial resize notification
    if (onResize) {
      onResize({ cols: term.cols, rows: term.rows });
    }

    return () => {
      window.removeEventListener('resize', handleResize);
      dataListenerRef.current?.dispose();
      webLinksAddon.dispose();
      fitAddon.dispose();
      term.dispose();
      writeQueueRef.current = [];
      pendingBytesRef.current = 0;
      isWritingRef.current = false;
      termRef.current = null;
      fitAddonRef.current = null;
    };
  }, []);

  // Update theme
  useEffect(() => {
    if (termRef.current && THEMES[theme]) {
      termRef.current.options.theme = THEMES[theme];
    }
  }, [theme]);

  // Update font size
  useEffect(() => {
    if (termRef.current) {
      termRef.current.options.fontSize = fontSize;
      fitAddonRef.current?.fit();
    }
  }, [fontSize]);

  return (
    <div ref={containerRef} className="xterm-wrapper" />
  );
});

XTermWrapper.displayName = 'XTermWrapper';

export default XTermWrapper;
