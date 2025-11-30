import React from 'react';
import { Tooltip } from 'antd';
import './IconButton.css';

/**
 * IconButton - A styled button wrapper for icons
 * @param {Object} props
 * @param {React.ReactNode} props.icon - The icon to display
 * @param {string} props.tooltip - Tooltip text
 * @param {function} props.onClick - Click handler
 * @param {boolean} props.active - Whether button is in active state
 * @param {boolean} props.disabled - Whether button is disabled
 * @param {'default' | 'primary' | 'danger'} props.variant - Button variant
 * @param {'sm' | 'md' | 'lg'} props.size - Button size
 * @param {string} props.className - Additional class names
 */
const IconButton = ({
  icon,
  tooltip,
  onClick,
  active = false,
  disabled = false,
  variant = 'default',
  size = 'md',
  className = '',
  ...rest
}) => {
  const buttonContent = (
    <button
      className={`icon-button icon-button--${variant} icon-button--${size} ${active ? 'icon-button--active' : ''} ${className}`}
      onClick={onClick}
      disabled={disabled}
      {...rest}
    >
      {icon}
    </button>
  );

  if (tooltip) {
    return (
      <Tooltip title={tooltip} placement="top">
        {buttonContent}
      </Tooltip>
    );
  }

  return buttonContent;
};

export default IconButton;
