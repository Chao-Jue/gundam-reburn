"""Chrome smoke test on an isolated save file, never creates real matches."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from urllib.request import urlopen

from playwright.sync_api import sync_playwright

HERE = Path(__file__).resolve().parent
with tempfile.TemporaryDirectory() as folder:
    save = Path(folder) / 'matches.json'
    process = subprocess.Popen([sys.executable, str(HERE / 'app.py'), '--port', '8766', '--save', str(save)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(80):
            try:
                urlopen('http://127.0.0.1:8766', timeout=1).close()
                break
            except OSError: time.sleep(.2)
        with sync_playwright() as p:
            browser = p.chromium.launch(executable_path='C:/Program Files/Google/Chrome/Application/chrome.exe',
                                       headless=True, args=['--use-angle=swiftshader', '--enable-unsafe-swiftshader'])
            page = browser.new_page(viewport={'width': 1600, 'height': 1000})
            errors = []
            page.on('pageerror', lambda e: errors.append(str(e)))
            page.goto('http://127.0.0.1:8766')
            page.wait_for_function("document.querySelector('#stageStatus').textContent.includes('三角形')")
            page.locator('#unitSearch').fill('吉姆')
            page.wait_for_function("[...document.querySelectorAll('#results img')].some(i=>i.complete && i.naturalWidth>0)", timeout=30000)
            page.locator('#results input').first.check()
            assert page.locator('#save').bounding_box()['y'] < 150
            # Assign the actual local DDS to the main body mesh, test image decode/render.
            texture_select = page.locator('#meshes select').last
            texture_select.select_option(index=1)
            page.wait_for_load_state('networkidle')
            page.locator('#notes').fill('UI smoke test only')
            assert page.locator('#save').bounding_box()['y'] < 150, 'save bar must remain visible while scrolling'
            page.locator('#save').click()
            page.wait_for_function("document.querySelector('#notice').textContent.includes('已保存')")
            stored = json.loads(save.read_text('utf8'))['matches']
            gm = next(iter(stored.values()))
            assert gm['model_id'] == 101010101 and gm['textures'] and gm['model_sha256']
            assert gm['texture_flip_y'] is False, 'DXG DDS UVs need unflipped textures'
            page.reload()
            page.wait_for_function("document.querySelector('#stageStatus').textContent.includes('三角形')")
            page.wait_for_load_state('networkidle')
            assert page.locator('#notes').input_value() == 'UI smoke test only'
            assert '吉姆' in page.locator('#selected').inner_text()
            assert page.locator('#meshes select').last.input_value()
            page.screenshot(path=str(HERE / 'preview.png'))
            response = page.request.get('http://127.0.0.1:8766/api/export')
            assert response.json()['matches'] == stored
            assert not errors, errors
            browser.close()
        print('PASS: 3D load, DDS render, select, save, reload and export; isolated save only')
    finally:
        process.terminate()
        process.wait(timeout=10)
