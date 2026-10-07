import { describe, expect, it } from 'vitest'
import { detectLanguage, EDITOR_LANGS } from './editorLang'

describe('detectLanguage — extensii', () => {
  it.each([
    ['deploy.sh', 'shell'], ['run.bash', 'shell'], ['x.zsh', 'shell'],
    ['compose.yml', 'yaml'], ['values.YAML', 'yaml'],
    ['package.json', 'json'], ['tsconfig.jsonc', 'json'], ['site.webmanifest', 'json'],
    ['php.ini', 'ini'], ['app.properties', 'ini'], ['my.cnf', 'ini'], ['app.conf', 'ini'],
    ['nginx.service', 'ini'], ['backup.timer', 'ini'], ['docker.socket', 'ini'], ['prod.env', 'ini'],
    ['pyproject.toml', 'toml'],
    ['main.py', 'python'], ['app.js', 'javascript'], ['vite.config.mjs', 'javascript'],
    ['index.ts', 'typescript'], ['App.tsx', 'typescript'],
    ['dump.sql', 'sql'], ['pom.xml', 'xml'], ['icon.svg', 'xml'], ['index.html', 'html'],
    ['style.css', 'css'], ['theme.scss', 'css'], ['README.md', 'markdown'],
    ['main.go', 'go'], ['lib.rs', 'rust'], ['index.php', 'php'], ['app.rb', 'ruby'],
    ['init.lua', 'lua'], ['script.pl', 'perl'], ['setup.ps1', 'powershell'],
    ['main.c', 'cpp'], ['x.hpp', 'cpp'], ['Main.java', 'java'], ['main.tf', 'hcl'],
    ['prod.Dockerfile', 'dockerfile'],
    ['notes.txt', 'plaintext'], ['syslog.log', 'plaintext'], ['blob.bin', 'plaintext'],
  ])('%s → %s', (name, lang) => {
    expect(detectLanguage(name)).toBe(lang)
  })
})

describe('detectLanguage — nume bine-cunoscute', () => {
  it.each([
    ['Dockerfile', 'dockerfile'], ['Containerfile', 'dockerfile'], ['Dockerfile.prod', 'dockerfile'],
    ['Dockerfile-dev', 'dockerfile'],
    ['Makefile', 'shell'], ['.bashrc', 'shell'], ['.bash_profile', 'shell'], ['.zshrc', 'shell'],
    ['.profile', 'shell'], ['PKGBUILD', 'shell'],
    ['.env', 'ini'], ['.env.local', 'ini'], ['.env.production', 'ini'], ['.gitconfig', 'ini'],
    ['.editorconfig', 'ini'], ['.eslintrc', 'json'],
    ['Cargo.lock', 'toml'], ['Pipfile', 'toml'],
    ['Gemfile', 'ruby'], ['Vagrantfile', 'ruby'],
    ['nginx.conf', 'nginx'], ['my-nginx.conf', 'nginx'],
  ])('%s → %s', (name, lang) => {
    expect(detectLanguage(name)).toBe(lang)
  })

  it('numele contează doar ca basename, oricât de adâncă e calea', () => {
    expect(detectLanguage('/home/me/app/Dockerfile')).toBe('dockerfile')
    expect(detectLanguage('/root/.bashrc')).toBe('shell')
    expect(detectLanguage('/srv/my.dockerfile.d/x.txt')).toBe('plaintext')
  })
})

describe('detectLanguage — nginx după cale', () => {
  it('tot ce e sub /etc/nginx/ e sintaxă nginx, cu sau fără extensie', () => {
    expect(detectLanguage('/etc/nginx/nginx.conf')).toBe('nginx')
    expect(detectLanguage('/etc/nginx/sites-available/default')).toBe('nginx')
    expect(detectLanguage('/etc/nginx/conf.d/app.conf')).toBe('nginx')
    expect(detectLanguage('/etc/nginx/snippets/ssl.conf')).toBe('nginx')
    expect(detectLanguage('/etc/nginx/fastcgi_params')).toBe('nginx')
  })
  it('dar fişierele cu alt format din /etc/nginx/ îşi păstrează limbajul', () => {
    expect(detectLanguage('/etc/nginx/html/index.html')).toBe('html')
    expect(detectLanguage('/etc/nginx/njs/auth.js')).toBe('javascript')
    expect(detectLanguage('/etc/nginx/ssl/cert.pem')).toBe('plaintext')
  })
  it('un .conf oarecare (în afara nginx) rămâne ini', () => {
    expect(detectLanguage('/etc/sysctl.d/99-local.conf')).toBe('ini')
    expect(detectLanguage('/etc/systemd/system/app.service')).toBe('ini')
  })
})

describe('detectLanguage — shebang şi antet', () => {
  it.each([
    ['#!/bin/sh', 'shell'], ['#!/bin/bash -e', 'shell'], ['#!/usr/bin/env bash', 'shell'],
    ['#!/usr/bin/env zsh', 'shell'], ['#! /bin/dash', 'shell'],
    ['#!/usr/bin/python3', 'python'], ['#!/usr/bin/env python3.12', 'python'],
    ['#!/usr/bin/env -S python3 -u', 'python'], ['#!/usr/bin/env PYTHONUNBUFFERED=1 python3', 'python'],
    ['#!/usr/bin/env node', 'javascript'], ['#!/usr/bin/perl -w', 'perl'],
    ['#!/usr/bin/env ruby', 'ruby'], ['#!/usr/bin/php', 'php'], ['#!/usr/bin/env lua5.4', 'lua'],
    ['#!/usr/bin/env pwsh', 'powershell'],
    ['#!/usr/bin/awk -f', 'plaintext'], ['# just a comment', 'plaintext'],
  ])('fără extensie + „%s" → %s', (first, lang) => {
    expect(detectLanguage('/usr/local/bin/tool', first)).toBe(lang)
  })
  it('extensia bate shebang-ul (un .py cu #!/bin/sh e tot python)', () => {
    expect(detectLanguage('x.py', '#!/bin/sh')).toBe('python')
  })
  it('<?xml pe prima linie → xml', () => {
    expect(detectLanguage('/etc/fonts/local', '<?xml version="1.0"?>')).toBe('xml')
  })
})

describe('detectLanguage — robusteţe', () => {
  it('nume goale / ciudate → plaintext, niciodată excepţie', () => {
    for (const n of ['', '.', '..', '/', 'a.', '.hidden', 'UPPER.UNKNOWN']) {
      expect(EDITOR_LANGS).toContain(detectLanguage(n))
    }
    expect(detectLanguage('a.')).toBe('plaintext')
    expect(detectLanguage('.hidden')).toBe('plaintext')
  })
  it('fiecare rezultat e un limbaj inclus în editor', () => {
    const names = ['a.sh', 'a.yml', 'a.json', 'a.toml', 'Dockerfile', 'nginx.conf', 'a.hcl', 'x']
    for (const n of names) expect(EDITOR_LANGS).toContain(detectLanguage(n))
  })
})
