#!/bin/bash

###############################################################################
# Rocket C2 Framework - Aggressive Dependency Upgrade Script
# Upgrades: React 18 + Ant Design 5 + All Dependencies
# Risk Level: HIGH - Full modernization
###############################################################################

set -e  # Exit on error

echo "=========================================="
echo "Rocket C2 - Aggressive Upgrade Script"
echo "=========================================="
echo ""
echo "This will upgrade:"
echo "  - React 17 → 18.3.1"
echo "  - Ant Design 4 → 5"
echo "  - React Router 6.2 → 6.26"
echo "  - All build tools and dependencies"
echo ""
echo "⚠️  WARNING: This is a HIGH RISK upgrade!"
echo ""
read -p "Continue? (yes/no): " confirm
if [ "$confirm" != "yes" ]; then
    echo "Upgrade cancelled."
    exit 0
fi

echo ""
echo "=========================================="
echo "Step 1: Backup Current State"
echo "=========================================="

cd /root/Rocket/web

# Create backup directory
BACKUP_DIR="/root/Rocket/backups/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

echo "Creating backups in $BACKUP_DIR..."
cp package.json "$BACKUP_DIR/package.json.backup"
cp package-lock.json "$BACKUP_DIR/package-lock.json.backup"
cp -r src "$BACKUP_DIR/src_backup"

echo "✅ Backup complete: $BACKUP_DIR"
echo ""

echo "=========================================="
echo "Step 2: Update Package Dependencies"
echo "=========================================="

echo "Installing React 18..."
npm install react@18.3.1 react-dom@18.3.1 --save

echo "Installing React Router 6.26..."
npm install react-router@6.26.2 react-router-dom@6.26.2 --save

echo "Installing Ant Design 5..."
npm install antd@5.22.5 --save
npm install @ant-design/icons@5.5.1 --save

echo "Installing Ant Design Pro Components (v5 compatible)..."
npm install @ant-design/pro-form@2.32.2 --save
npm install @ant-design/pro-layout@7.21.1 --save
npm install @ant-design/pro-table@3.19.1 --save

echo "Removing Ant Design v4 webpack plugin..."
npm uninstall antd-dayjs-webpack-plugin --save-dev

echo "Installing other core dependencies..."
npm install axios@1.7.9 --save
npm install dayjs@1.11.13 --save
npm install i18next@23.17.4 --save
npm install lodash@4.17.21 --save

echo "Installing terminal dependencies..."
npm install xterm@5.5.0 --save
npm install xterm-addon-fit@0.10.0 --save
npm install xterm-addon-web-links@0.11.0 --save

echo "Installing editor and other libraries..."
npm install ace-builds@1.38.0 --save
npm install react-ace@12.0.0 --save
npm install react-markdown@9.0.1 --save

echo "Installing build tools..."
npm install webpack@5.97.1 --save-dev
npm install webpack-cli@5.1.4 --save-dev
npm install webpack-dev-server@5.1.0 --save-dev
npm install esbuild@0.24.2 --save-dev
npm install esbuild-loader@4.2.2 --save-dev

echo "Installing CSS/LESS loaders..."
npm install css-loader@7.1.2 --save-dev
npm install style-loader@4.0.0 --save-dev
npm install less@4.2.1 --save-dev
npm install less-loader@12.2.0 --save-dev

echo "Installing other webpack plugins..."
npm install html-webpack-plugin@5.6.3 --save-dev
npm install compression-webpack-plugin@11.1.0 --save-dev
npm install copy-webpack-plugin@12.0.2 --save-dev
npm install clean-webpack-plugin@4.0.0 --save-dev

echo "✅ All dependencies updated"
echo ""

echo "=========================================="
echo "Step 3: Check for antd CSS imports"
echo "=========================================="

echo "Searching for 'antd/dist/antd.css' imports..."
if grep -r "antd/dist/antd.css" src/ 2>/dev/null; then
    echo ""
    echo "⚠️  Found antd CSS imports - these need to be removed!"
    echo "Please review and remove them manually."
    echo ""
else
    echo "✅ No antd CSS imports found (or already removed)"
    echo ""
fi

echo "=========================================="
echo "Step 4: Upgrade Summary"
echo "=========================================="

echo ""
echo "Package versions installed:"
npm list react react-dom react-router react-router-dom antd @ant-design/icons axios webpack 2>/dev/null | head -20

echo ""
echo "=========================================="
echo "Next Steps - MANUAL CODE CHANGES REQUIRED"
echo "=========================================="
echo ""
echo "1. Update /root/Rocket/web/src/index.jsx:"
echo "   - Change: import ReactDOM from 'react-dom'"
echo "   - To:     import { createRoot } from 'react-dom/client'"
echo ""
echo "   - Change: ReactDOM.render(<App/>, document.getElementById('root'))"
echo "   - To:     createRoot(document.getElementById('root')).render(<App/>)"
echo ""
echo "2. Remove ALL 'import antd/dist/antd.css' lines from:"
echo "   - /root/Rocket/web/src/index.jsx"
echo "   - Any other component files"
echo ""
echo "3. Update webpack.config.js:"
echo "   - Remove antd-dayjs-webpack-plugin (already uninstalled)"
echo ""
echo "4. Fix Ant Design v5 component API changes:"
echo "   - Form.Item 'name' prop behavior changed"
echo "   - Some component props renamed/removed"
echo "   - Check: https://ant.design/docs/react/migration-v5"
echo ""
echo "5. Test build:"
echo "   cd /root/Rocket/web"
echo "   NODE_ENV=production npx webpack --mode production"
echo ""
echo "6. Fix any compilation errors and rebuild"
echo ""
echo "=========================================="
echo "Rollback Instructions"
echo "=========================================="
echo ""
echo "If upgrade fails, restore from backup:"
echo "  cp $BACKUP_DIR/package.json.backup /root/Rocket/web/package.json"
echo "  cp $BACKUP_DIR/package-lock.json.backup /root/Rocket/web/package-lock.json"
echo "  cd /root/Rocket/web"
echo "  npm install"
echo ""
echo "=========================================="
echo "Upgrade preparation complete!"
echo "=========================================="
