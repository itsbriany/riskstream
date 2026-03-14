# AGENTS.md

## Core Rules
- Prefer minimal, targeted changes.
- Do not refactor unrelated code.
- Do not rename functions or variables unless requested.
- Follow the existing style in the file.
- When writing integration tests, they should test the services from within the kubernetes cluster.

## Decision Checklist
Before editing, determine:
1. What is the smallest change that solves the task?
2. Can this be done in one file?
3. Will this break any existing interface?
4. Am I touching unrelated code?

## Change Budget
- Default to a single-file diff.
- If more than one file is required, explain why first.
- Avoid large rewrites or formatting-only edits.
- Keep the diff easy to review.

## Before Editing
Briefly state what will change and which file(s) will be touched.