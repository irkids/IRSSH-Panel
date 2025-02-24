#!/bin/bash
echo "Starting TypeScript build using tsconfig.build.json..."
npx tsc -p tsconfig.build.json || { echo "TypeScript build failed"; exit 1; }

echo "Starting Vite build..."
npx vite build || { echo "Vite build failed"; exit 1; }
