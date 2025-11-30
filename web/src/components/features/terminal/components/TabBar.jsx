import React from 'react';
import { PlusOutlined, CloseOutlined } from '@ant-design/icons';
import { Tooltip } from 'antd';
import { StatusBadge } from '../../../shared';
import './Terminal.css';

/**
 * TabBar - Multi-session tab bar for terminal
 */
const TabBar = ({
  sessions,
  activeSessionId,
  onSelectSession,
  onNewSession,
  onCloseSession,
}) => {
  return (
    <div className="terminal-tabbar">
      <div className="terminal-tabs">
        {sessions.map((session, index) => (
          <div
            key={session.id}
            className={`terminal-tab ${session.id === activeSessionId ? 'terminal-tab--active' : ''}`}
            onClick={() => onSelectSession(session.id)}
          >
            <StatusBadge
              status={session.status}
              className="terminal-tab-status"
            />
            <span className="terminal-tab-title">
              {session.title || `Session ${index + 1}`}
            </span>
            <button
              className="terminal-tab-close"
              onClick={(e) => {
                e.stopPropagation();
                onCloseSession(session.id);
              }}
            >
              <CloseOutlined />
            </button>
          </div>
        ))}
      </div>
      <Tooltip title="New session">
        <button className="terminal-new-tab" onClick={onNewSession}>
          <PlusOutlined />
        </button>
      </Tooltip>
    </div>
  );
};

export default TabBar;
