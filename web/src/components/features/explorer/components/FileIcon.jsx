import React from 'react';
import {
  FileOutlined,
  FolderOutlined,
  FolderOpenOutlined,
  FileImageOutlined,
  FileTextOutlined,
  FilePdfOutlined,
  FileZipOutlined,
  FileExcelOutlined,
  FileWordOutlined,
  FilePptOutlined,
  PlayCircleOutlined,
  SoundOutlined,
  CodeOutlined,
  DatabaseOutlined,
  HddOutlined,
  ArrowUpOutlined,
} from '@ant-design/icons';
import './Explorer.css';

// File type mappings
const FILE_TYPES = {
  // Images
  image: ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'svg', 'webp', 'ico'],
  // Documents
  pdf: ['pdf'],
  word: ['doc', 'docx', 'odt', 'rtf'],
  excel: ['xls', 'xlsx', 'csv', 'ods'],
  powerpoint: ['ppt', 'pptx', 'odp'],
  text: ['txt', 'md', 'log'],
  // Code
  code: ['js', 'jsx', 'ts', 'tsx', 'py', 'java', 'c', 'cpp', 'h', 'go', 'rs', 'rb', 'php', 'html', 'css', 'scss', 'json', 'xml', 'yaml', 'yml', 'sh', 'bash', 'sql'],
  // Archives
  archive: ['zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'xz'],
  // Media
  video: ['mp4', 'avi', 'mkv', 'mov', 'wmv', 'flv', 'webm'],
  audio: ['mp3', 'wav', 'ogg', 'flac', 'aac', 'm4a'],
  // Database
  database: ['db', 'sqlite', 'mdb'],
};

const getFileType = (filename) => {
  const ext = filename.split('.').pop()?.toLowerCase() || '';
  for (const [type, extensions] of Object.entries(FILE_TYPES)) {
    if (extensions.includes(ext)) {
      return type;
    }
  }
  return 'file';
};

const getTypeColor = (type) => {
  const colors = {
    folder: '#ffc107',
    image: '#4caf50',
    pdf: '#f44336',
    word: '#2196f3',
    excel: '#4caf50',
    powerpoint: '#ff5722',
    text: '#9e9e9e',
    code: '#9c27b0',
    archive: '#795548',
    video: '#e91e63',
    audio: '#00bcd4',
    database: '#ff9800',
    disk: '#607d8b',
    file: '#9e9e9e',
  };
  return colors[type] || colors.file;
};

/**
 * FileIcon - Displays an icon based on file type
 */
const FileIcon = ({ file, size = 'md', isOpen = false }) => {
  const getIcon = () => {
    // Special cases
    if (file.name === '..') {
      return <ArrowUpOutlined />;
    }

    // Disk (type 2)
    if (file.type === 2) {
      return <HddOutlined />;
    }

    // Folder (type 1)
    if (file.type === 1) {
      return isOpen ? <FolderOpenOutlined /> : <FolderOutlined />;
    }

    // File (type 0)
    const fileType = getFileType(file.name);
    switch (fileType) {
      case 'image':
        return <FileImageOutlined />;
      case 'pdf':
        return <FilePdfOutlined />;
      case 'word':
        return <FileWordOutlined />;
      case 'excel':
        return <FileExcelOutlined />;
      case 'powerpoint':
        return <FilePptOutlined />;
      case 'text':
        return <FileTextOutlined />;
      case 'code':
        return <CodeOutlined />;
      case 'archive':
        return <FileZipOutlined />;
      case 'video':
        return <PlayCircleOutlined />;
      case 'audio':
        return <SoundOutlined />;
      case 'database':
        return <DatabaseOutlined />;
      default:
        return <FileOutlined />;
    }
  };

  const getTypeForColor = () => {
    if (file.type === 2) return 'disk';
    if (file.type === 1) return 'folder';
    return getFileType(file.name);
  };

  const sizeClass = `file-icon--${size}`;
  const color = getTypeColor(getTypeForColor());

  return (
    <span className={`file-icon ${sizeClass}`} style={{ color }}>
      {getIcon()}
    </span>
  );
};

export default FileIcon;
