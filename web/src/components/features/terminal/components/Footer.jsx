import React from 'react';
import { UploadOutlined, DownloadOutlined, BgColorsOutlined, FontSizeOutlined, ClearOutlined, ReloadOutlined } from '@ant-design/icons';
import { Dropdown } from 'antd';
import { IconButton } from '../../../shared';
import './Terminal.css';

// Quick commands for common operations
const QUICK_COMMANDS = [
  { key: 'clear', label: 'Clear', command: 'clear' },
  { key: 'pwd', label: 'PWD', command: 'pwd' },
  { key: 'ls', label: 'List', command: 'ls -la' },
  { key: 'top', label: 'Top', command: 'top' },
  { key: 'df', label: 'Disk', command: 'df -h' },
  { key: 'free', label: 'Memory', command: 'free -h' },
];

const THEMES = [
  { key: 'dark', label: 'Dark' },
  { key: 'light', label: 'Light' },
  { key: 'monokai', label: 'Monokai' },
  { key: 'dracula', label: 'Dracula' },
  { key: 'retro', label: 'Retro Green' },
];

const FONT_SIZES = [12, 14, 16, 18, 20, 24];

/**
 * Footer - Terminal footer with quick commands and actions
 */
const Footer = ({
  os,
  onQuickCommand,
  onUpload,
  onDownload,
  onClear,
  onReconnect,
  theme,
  onThemeChange,
  fontSize,
  onFontSizeChange,
  status,
}) => {
  const isWindows = os?.toLowerCase().includes('windows');
  const isConnected = status === 'connected';

  const themeMenu = {
    items: THEMES,
    selectedKeys: [theme],
    onClick: ({ key }) => onThemeChange(key),
  };

  const fontSizeMenu = {
    items: FONT_SIZES.map((size) => ({
      key: String(size),
      label: `${size}px`,
    })),
    selectedKeys: [String(fontSize)],
    onClick: ({ key }) => onFontSizeChange(Number(key)),
  };

  return (
    <div className="terminal-footer">
      <div className="terminal-footer-left">
        {/* Quick commands - only for Unix-like systems */}
        {!isWindows && (
          <div className="terminal-quick-commands">
            {QUICK_COMMANDS.map((cmd) => (
              <button
                key={cmd.key}
                className="terminal-quick-command"
                onClick={() => onQuickCommand(cmd.command)}
                disabled={!isConnected}
              >
                {cmd.label}
              </button>
            ))}
          </div>
        )}
      </div>

      <div className="terminal-footer-right">
        {/* File transfer buttons - only for Unix-like with Zmodem */}
        {!isWindows && (
          <>
            <IconButton
              icon={<UploadOutlined />}
              tooltip="Upload file (sz)"
              onClick={onUpload}
              disabled={!isConnected}
              size="sm"
            />
            <IconButton
              icon={<DownloadOutlined />}
              tooltip="Download file (rz)"
              onClick={onDownload}
              disabled={!isConnected}
              size="sm"
            />
            <div className="terminal-footer-divider" />
          </>
        )}

        {/* Theme selector */}
        <Dropdown menu={themeMenu} trigger={['click']}>
          <IconButton
            icon={<BgColorsOutlined />}
            tooltip="Change theme"
            size="sm"
          />
        </Dropdown>

        {/* Font size selector */}
        <Dropdown menu={fontSizeMenu} trigger={['click']}>
          <IconButton
            icon={<FontSizeOutlined />}
            tooltip="Font size"
            size="sm"
          />
        </Dropdown>

        <div className="terminal-footer-divider" />

        {/* Clear terminal */}
        <IconButton
          icon={<ClearOutlined />}
          tooltip="Clear terminal"
          onClick={onClear}
          disabled={!isConnected}
          size="sm"
        />

        {/* Reconnect */}
        <IconButton
          icon={<ReloadOutlined />}
          tooltip="Reconnect"
          onClick={onReconnect}
          disabled={status === 'connecting'}
          size="sm"
        />
      </div>
    </div>
  );
};

export default Footer;
