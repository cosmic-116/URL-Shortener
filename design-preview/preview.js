'use strict';

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const esc = value => String(value ?? '').replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
const icons = {
  arrow:'<path d="M4 12h15m-6-6 6 6-6 6"/>', up:'<path d="M7 17 17 7M7 7h10v10"/>',
  link:'<path d="M10 13a5 5 0 0 0 7 .3l3-3a5 5 0 0 0-7-7l-1.7 1.7M14 11a5 5 0 0 0-7-.3l-3 3a5 5 0 0 0 7 7l1.7-1.7"/>',
  copy:'<rect x="8" y="8" width="12" height="12" rx="2"/><path d="M16 8V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h3"/>',
  check:'<path d="m5 12 4 4L19 6"/>', plus:'<path d="M12 5v14M5 12h14"/>',
  grid:'<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>',
  chart:'<path d="M4 4v16h16M8 15l4-5 4 3 4-7"/>',
  qr:'<path d="M3 3h7v7H3zm11 0h7v7h-7zM3 14h7v7H3zm11 0h3v3h-3zm4 4h3v3h-3zm3-4v1m-7 6v-1"/>',
  settings:'<path d="M12 3v3m0 12v3M3 12h3m12 0h3M5.6 5.6l2.1 2.1m8.6 8.6 2.1 2.1M5.6 18.4l2.1-2.1m8.6-8.6 2.1-2.1"/><circle cx="12" cy="12" r="5"/>',
  code:'<path d="m8 6-6 6 6 6m8-12 6 6-6 6m-3-15-2 18"/>',
  search:'<circle cx="10.5" cy="10.5" r="6.5"/><path d="m16 16 5 5"/>',
  chevron:'<path d="m8 10 4 4 4-4"/>', close:'<path d="m6 6 12 12M6 18 18 6"/>',
  trash:'<path d="M3 6h18M9 6V3h6v3M5 6l1 15h12l1-15M10 10v7m4-7v7"/>',
  download:'<path d="M12 3v12m-5-5 5 5 5-5M4 17v4h16v-4"/>',
  shield:'<path d="m12 3 8 3v6c0 5-8 9-8 9s-8-4-8-9V6z"/><path d="m8 12 3 3 5-6"/>',
  mail:'<rect x="3" y="5" width="18" height="14" rx="2"/><path d="m3 6 9 7 9-7"/>',
  eye:'<path d="M2 12s4-7 10-7 10 7 10 7-4 7-10 7-10-7-10-7"/><circle cx="12" cy="12" r="3"/>',
  clock:'<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  alert:'<path d="m12 3 10 18H2zM12 9v5m0 3v1"/>',
  menu:'<path d="M4 6h16M4 12h16M4 18h16"/>', logout:'<path d="M9 4H4v16h5m5-13 5 5-5 5m-6-5h11"/>',
  device:'<rect x="3" y="4" width="18" height="13" rx="1"/><path d="M8 21h8m-4-4v4"/>',
  key:'<circle cx="8" cy="9" r="5"/><path d="m12 13 8 8m-4-4 3-3m-6 0 3-3"/>',
  globe:'<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c-5 5-5 13 0 18m0-18c5 5 5 13 0 18"/>',
  scissors:'<g class="scissor-arm"><circle cx="6" cy="18" r="3"/><path d="M8 16 20 4"/></g><g class="scissor-arm"><circle cx="6" cy="6" r="3"/><path d="M8 8 20 20"/></g>',
  back:'<path d="M20 12H5m6-6-6 6 6 6"/>', spark:'<path d="m12 3 2.5 6.5L21 12l-6.5 2.5L12 21l-2.5-6.5L3 12l6.5-2.5z"/>'
};
const icon = name => `<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${icons[name] || icons.link}</svg>`;
const brand = () => `<a class="brand" href="#home" aria-label="Snip homepage"><span class="brand-mark">${icon('scissors')}</span>snip<span class="brand-dot"></span></a>`;
const btn = (label, action, style = '', ico = '') => `<button type="button" class="btn ${style}" data-action="${action}">${esc(label)}${ico ? icon(ico) : ''}</button>`;
const badge = (text, style = '') => `<span class="badge ${style}"><span class="dot"></span>${esc(text)}</span>`;
const seedLinks = [
  {id:'launch',title:'The October launch',code:'october',url:'https://snip-it.me/product/launch',clicks:1248,date:'Oct 08, 2026',ad:'off',safe:'checked',mark:'S'},
  {id:'portfolio',title:'Design portfolio',code:'folio',url:'https://www.behance.net/princegupta',clicks:863,date:'Oct 07, 2026',ad:'network',safe:'checked',mark:'Bē'},
  {id:'video',title:'A little behind the scenes',code:'bts',url:'https://www.youtube.com/watch?v=sample',clicks:527,date:'Oct 06, 2026',ad:'off',safe:'checked',mark:'▶'},
  {id:'guide',title:'Getting started with Snip',code:'start',url:'https://github.com/cosmic-116/URL-Shortener',clicks:321,date:'Oct 05, 2026',ad:'custom',safe:'unchecked',mark:'G'},
  {id:'invite',title:'A seat at the table',code:'invite',url:'https://example.com/community/invitation',clicks:118,date:'Oct 04, 2026',ad:'off',safe:'checked',mark:'↗'}
];
const state = { links:structuredClone(seedLinks), guests:5, query:'',sort:'newest',chart:'week',settings:'profile',email:'prince.gupta@snip-it.me',name:'Prince Gupta',username:'princegupta',verifyPurpose:'register',preferences:{securityEmails:true,defaultAds:false},qr:{...SnipQRStudio.defaults},timer:null,selected:'launch',emailType:'registration',signedIn:false };
const screens = [['home','Homepage'],['dashboard','Overview'],['links','Your links'],['analytics','Analytics'],['qr','QR Studio'],['account','Account'],['api','Developer API'],['login','Log in'],['register','Sign up'],['verify','Verify email'],['success','Welcome / API key'],['forgot','Forgot password'],['reset','Reset password'],['transit','Ad transit'],['warning','Safety warning'],['expired','Expired link'],['empty','Empty dashboard'],['guest-limit','Guest limit'],['404','Not found'],['403','Forbidden'],['429','Rate limit'],['500','Server error'],['400','Bad request'],['405','Wrong method'],['413','Too large'],['emails','Email templates']];
const app = $('#app');
let route = 'home';
let toastTimer;

function toast(message) {
  clearTimeout(toastTimer);
  $('#toast-region').innerHTML = `<div class="toast">${icon('check')}${esc(message)}</div>`;
  toastTimer = setTimeout(() => $('#toast-region').replaceChildren(), 3200);
}

async function copy(text) {
  try { await navigator.clipboard.writeText(text); toast('Copied to your clipboard.'); }
  catch { showModal('Copy this link', `<p>Your browser blocked clipboard access. Select the text below to copy it.</p><div class="field"><label for="manual-copy">Link</label><input id="manual-copy" readonly value="${esc(text)}"></div>`); $('#manual-copy').select(); }
}

function showModal(title, body, actions = '') {
  const modal = $('#modal');
  if (modal.open) modal.close();
  modal.setAttribute('aria-labelledby','modal-title');
  modal.innerHTML = `<div class="modal-head"><h2 id="modal-title">${title}</h2><button class="icon-btn" data-action="close-modal" aria-label="Close dialog">${icon('close')}</button></div><div class="modal-body">${body}</div>${actions ? `<div class="modal-actions">${actions}</div>` : ''}`;
  modal.showModal();
}

function publicHeader() {
  return `<header class="public-header">${brand()}<nav class="public-nav" aria-label="Main navigation"><a class="nav-extra" href="#home" data-scroll="features">Explore Snip<span class="nav-index">01</span></a><a class="nav-extra" href="#api">For developers<span class="nav-index">02</span></a><a href="#login">Log in</a><a class="btn" href="#register">Get started ${icon('up')}</a></nav></header>`;
}
function footer() { return `<footer class="public-footer">${brand()}<span>© 2026 Snip. A little less link.</span><div class="footer-links"><a href="#api">Developer API</a><a href="mailto:prince.gupta@snip-it.me">Contact the CEO ${icon('up')}</a></div></footer>`; }
function chart(color = '#e5f45a', large = false) {
  return `<svg class="line-chart" viewBox="0 0 630 150" preserveAspectRatio="none" role="img" aria-label="Illustrative click activity rising over the past week"><defs><linearGradient id="chart-fade-${large?'home':'app'}" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="${color}" stop-opacity=".17"/><stop offset="100%" stop-color="${color}" stop-opacity="0"/></linearGradient></defs><path d="M0 25H630M0 65H630M0 105H630M0 145H630" stroke="#79836e" stroke-opacity=".2" fill="none"/><path d="M0 116C25 116 26 126 52 109S77 117 101 91 137 110 162 87 186 80 212 97 240 84 269 73 293 95 321 58 349 77 376 66 402 58 429 70 458 40 482 46 508 37 535 62 563 30 593 33 610 32 630 10L630 150H0Z" fill="url(#chart-fade-${large?'home':'app'})"/><path id="chart-line" d="M0 116C25 116 26 126 52 109S77 117 101 91 137 110 162 87 186 80 212 97 240 84 269 73 293 95 321 58 349 77 376 66 402 58 429 70 458 40 482 46 508 37 535 62 563 30 593 33 610 32 630 10" fill="none" stroke="${color}" stroke-width="2" vector-effect="non-scaling-stroke"/><circle cx="630" cy="10" r="4" fill="${color}"/></svg>`;
}

function qrSvg(fg = '#171b18', bg = '#fffefa', shape = 'square') {
  const matrix = window.SNIP_QR_MATRIX;
  const n = matrix.length, size = n + 8;
  const finder = (x,y) => (x<7&&y<7)||(x>=n-7&&y<7)||(x<7&&y>=n-7);
  let cells = '';
  matrix.forEach((row,y) => row.forEach((cell,x) => {
    if (!cell) return;
    if(shape==='dots'&&!finder(x,y)) cells += `<circle cx="${x+4.5}" cy="${y+4.5}" r=".47"/>`;
    else cells += `<rect x="${x+4}" y="${y+4}" width="1" height="1"${shape==='rounded'&&!finder(x,y)?' rx=".22"':''}/>`;
  }));
  return `<svg class="qr-svg" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" role="img" aria-label="Sample QR code for snip-it.me"><rect width="${size}" height="${size}" fill="${esc(bg)}"/><g fill="${esc(fg)}">${cells}</g></svg>`;
}

function renderHome() {
  app.innerHTML = `${publicHeader()}<main id="page"><section class="hero"><div class="hero-overline"><span class="tiny-rule"></span><span class="eyebrow">Good things come in shorter links.</span></div><div class="hero-grid"><h1>Big ideas.<br><span class="serif">Short</span> links.</h1><aside class="hero-note"><span class="number">A SMALL TOOL. A BIG DIFFERENCE.</span><p>Make it memorable. Share it anywhere. See what happens next.</p><a class="text-link" href="#dashboard">Take a look inside ${icon('up')}</a></aside></div><form id="home-shorten" class="shortener"><span class="shortener-icon">${icon('link')}</span><input type="url" name="url" aria-label="URL to shorten" placeholder="Your very long link goes here…" required><button class="btn accent" type="submit">Snip it ${icon('scissors')}</button></form><div class="shortener-meta"><span>Try the guest flow. <strong id="guest-count">${state.guests}</strong> free links per 2 hours.</span><button type="button" data-action="advanced" aria-expanded="false" aria-controls="advanced-home">Make it yours ${icon('plus')}</button><span class="meta-hide">One link. Endless possibilities.</span></div><div id="advanced-home" class="advanced" hidden><div class="form-grid"><div class="field"><label for="home-alias">Custom alias</label><input id="home-alias" form="home-shorten" name="alias" placeholder="your-big-idea" pattern="[A-Za-z0-9_-]{1,30}"><span class="hint">snip-it.me/your-big-idea</span></div><div class="field"><label for="home-expiry">Link expiry</label><select id="home-expiry" form="home-shorten" name="expiry"><option>Never</option><option>In 24 hours</option><option>In 7 days</option><option>In 30 days</option></select></div></div></div><div id="home-result" aria-live="polite"></div></section><div class="home-divider"><span class="label eyebrow">Less friction.<br>More possibilities.</span><div class="quiet-check">${icon('link')}<strong>Your link. Your name.</strong></div><div class="quiet-check">${icon('chart')}<strong>See every connection.</strong></div><div class="quiet-check">${icon('qr')}<strong>From screen to anywhere.</strong></div><div class="quiet-check">${icon('shield')}<strong>Share with confidence.</strong></div></div><section id="features" class="feature-section"><div class="feature-heading"><h2>A better way<br>to pass it <span class="serif">on.</span></h2><p>A launch. A portfolio. An invite worth sending. Whatever you’re sharing, give it a link that’s easy to remember and a place to see how it’s doing.</p></div><div class="feature-grid"><article class="feature-analytics"><div class="row between"><div><span class="eyebrow">01 / Know your audience</span><h3>Every click tells a story.</h3></div>${icon('up')}</div><div class="big-number">3,077<span style="font-size:11px;color:#98aa88;letter-spacing:0;margin-left:14px">↗ 24.6%</span></div><div class="chart-caption"><span>Connections this week</span><span>Illustrative data</span></div>${chart('#e5f45a',true)}</article><article class="feature-qr"><span class="eyebrow muted">02 / Beyond the browser</span><h3>Good on paper, too.</h3><p>A code on a menu. A link on a poster. Your idea, in the real world.</p><a class="text-link" href="#qr">Open QR Studio ${icon('up')}</a><div class="qr-art">${qrSvg()}</div></article></div><div class="feature-bottom"><article class="feature-line">${icon('shield')}<div><h3>Know where your link leads.</h3><p>Link safety checks, clear destination warnings, and controls that put you in charge.</p></div></article><article class="feature-line">${icon('code')}<div><h3>Fits right into your workflow.</h3><p>A straightforward developer API. Connect Snip to the tools you already use.</p></div></article></div></section><section class="home-cta"><div class="home-cta-inner"><div><p class="eyebrow muted">Make a little room for a big idea.</p><h2>Let’s make it <span class="serif">short.</span></h2></div><a class="btn" href="#register">Your free account ${icon('up')}</a></div></section></main>${footer()}`;
}

const navItems = [['dashboard','grid','Overview'],['links','link','Your links'],['qr','qr','QR Studio'],['analytics','chart','Analytics'],['account','settings','Account'],['api','code','Developer API']];
function shell(content, active = route) {
  const title = navItems.find(item=>item[0]===active)?.[2] || 'Your links';
  app.innerHTML = `<div class="app-shell"><aside class="sidebar" aria-label="Workspace navigation">${brand()}<p class="workspace-label">Your workspace</p><nav class="side-nav">${navItems.map(([id,ico,label])=>`<a href="#${id}" class="${id===active?'active':''}" ${id===active?'aria-current="page"':''}>${icon(ico)}${label}${id==='links'?`<span class="count">${state.links.length}</span>`:''}</a>`).join('')}</nav><div class="sidebar-bottom"><div class="side-demo"><span class="eyebrow">Your space to try things.</span><p>Ad transit is a demo. All balances and credits are simulated.</p><a href="#transit" style="display:inline-flex;gap:7px;margin-top:12px;font-size:10px;color:#e5f45a">See the experience ${icon('up')}</a></div><a class="sidebar-user" href="#account"><span class="avatar">PG</span><div><strong>${esc(state.name)}</strong><small>Personal workspace</small></div>${icon('chevron')}</a></div></aside><div class="app-canvas"><header class="app-topbar"><div class="breadcrumbs"><button class="icon-btn mobile-menu" data-action="menu" aria-label="Toggle workspace navigation">${icon('menu')}</button><span>Workspace</span><span>/</span><strong style="color:var(--ink);font-weight:500">${esc(title)}</strong></div><div class="row"><span class="top-date">Thursday, October 08</span><a class="btn ghost" href="#home">View website ${icon('up')}</a></div></header><main id="page" class="page-inner">${content}</main><footer class="app-footer"><span>Made for good connections.</span><a href="mailto:prince.gupta@snip-it.me">Contact the CEO · prince.gupta@snip-it.me</a></footer></div></div>`;
}
function metricCards() {
  const total = state.links.reduce((sum,link)=>sum+link.clicks,0);
  return `<section class="metrics" aria-label="Workspace totals"><div class="metric"><span class="label">Total clicks ${icon('chart')}</span><div class="number">${total.toLocaleString()}</div><div class="detail"><span class="up">↗ 24.6%</span> vs. last week</div></div><div class="metric"><span class="label">Active links</span><div class="number">${state.links.length.toString().padStart(2,'0')}</div><div class="detail">All your connections, in one place</div></div><div class="metric"><span class="label">Unique visitors</span><div class="number">2,418</div><div class="detail"><span class="up">↗ 18.2%</span> vs. last week</div></div><div class="metric"><span class="label">Demo ad balance <span class="demo-tag">SIMULATED</span></span><div class="number">$17.26</div><div class="detail">Demo credits. No real payouts.</div></div></section>`;
}
function activityChart() {
  return `<section class="chart-panel"><div class="row between"><div><p class="eyebrow">Click activity</p><p class="chart-sub" id="chart-sub">A good week for your ideas.</p></div><div class="segmented" role="group" aria-label="Activity period">${[['week','7 days'],['month','30 days'],['year','12 months']].map(([id,label])=>`<button data-action="chart" data-period="${id}" class="${state.chart===id?'active':''}" aria-pressed="${state.chart===id}">${label}</button>`).join('')}</div></div>${chart()}<div class="chart-labels"><span>FRI 02</span><span>SAT 03</span><span>SUN 04</span><span>MON 05</span><span>TUE 06</span><span>WED 07</span><span>THU 08</span></div></section>`;
}
function sources() { return `<section class="sources-panel"><h3>Where they found you</h3>${[['Direct',48],['Social',32],['Search',20]].map(([name,count])=>`<div class="source-item"><div class="source-label"><span>${name}</span><span class="mono">${count}%</span></div><div class="source-track"><span style="width:${count}%"></span></div></div>`).join('')}</section>`; }
function filteredLinks() {
  const query = state.query.toLowerCase();
  return state.links.filter(link=>[link.title,link.code,link.url].some(value=>value.toLowerCase().includes(query)));
}
function linkCountText() {
  return `Showing ${filteredLinks().length} of ${state.links.length} links · All times in your local timezone`;
}
function tableRows() {
  let links = filteredLinks();
  if(state.sort==='clicks') links.sort((a,b)=>b.clicks-a.clicks);
  if(state.sort==='oldest') links.reverse();
  if(!links.length) return `<tr><td colspan="6"><div class="empty-state" style="padding:35px"><h2>No matches.</h2><p>Try a different title, destination, or short link.</p>${btn('Clear search','clear-search','light')}</div></td></tr>`;
  return links.map(link=>`<tr><td><div class="link-cell"><span class="site-mark">${esc(link.mark)}</span><div><strong>${esc(link.title)}</strong><a href="#links" data-action="copy" data-code="${esc(link.code)}">snip-it.me/${esc(link.code)}</a></div></div></td><td><span class="destination-text" title="${esc(link.url)}">${esc(link.url.replace('https://',''))}</span></td><td class="mono">${link.clicks.toLocaleString()}</td><td><button type="button" class="badge ${link.ad==='off'?'neutral':'amber'}" style="border:0" data-action="ad-settings" data-id="${link.id}" aria-label="Configure demo ads for ${esc(link.title)}">${link.ad==='off'?'Ads off':link.ad==='network'?'Network · demo':'Custom · demo'}${icon('chevron')}</button></td><td>${badge(link.safe==='checked'?'Checked':'Unchecked',link.safe==='checked'?'':'neutral')}</td><td><div class="table-actions"><button class="icon-btn" data-action="copy" data-code="${esc(link.code)}" aria-label="Copy ${esc(link.title)}">${icon('copy')}</button><button class="icon-btn" data-action="link-qr" data-id="${link.id}" aria-label="QR code for ${esc(link.title)}">${icon('qr')}</button><button class="icon-btn" data-action="delete" data-id="${link.id}" aria-label="Delete ${esc(link.title)}">${icon('trash')}</button></div></td></tr>`).join('');
}
function linksTable() {
  return `<section aria-label="Link manager"><div class="links-toolbar"><h2>Your links <span>${state.links.length} connections</span></h2><div class="table-controls"><div class="search-field">${icon('search')}<input id="link-search" aria-label="Search links" placeholder="Find a link…" value="${esc(state.query)}"></div><select id="link-sort" aria-label="Sort links"><option value="newest" ${state.sort==='newest'?'selected':''}>Newest first</option><option value="clicks" ${state.sort==='clicks'?'selected':''}>Most clicks</option><option value="oldest" ${state.sort==='oldest'?'selected':''}>Oldest first</option></select></div></div><table class="link-table"><thead><tr><th>Link</th><th>Destination</th><th>Clicks</th><th>Ad transit</th><th>Safety</th><th>Actions</th></tr></thead><tbody id="link-rows">${tableRows()}</tbody></table><div class="table-bottom"><span id="link-count">${linkCountText()}</span><div class="pagination"><button disabled aria-label="Previous page">←</button><button class="active" aria-current="page">1</button><button disabled aria-label="Next page">→</button></div></div></section>`;
}
function renderDashboard(view = 'dashboard') {
  const empty = view==='empty';
  const title = view==='links'?'A home for your links.':`Welcome back, ${esc(state.name.split(' ')[0])}.`;
  shell(`<div class="page-title"><div><p class="eyebrow">${view==='links'?'Link library':'Your overview'}</p><h1>${title}</h1><p>${view==='links'?'Find it, share it, see how it’s doing.':'A clear view of what you’ve shared—and where it’s going.'}</p></div>${btn('New link','new-link','','plus')}</div>${view!=='links'&&!empty?metricCards():''}${view==='dashboard'?`<div class="overview-grid">${activityChart()}${sources()}</div>`:''}${empty?`<div class="empty-state"><div class="empty-art">${icon('link')}</div><span class="eyebrow muted" style="margin-bottom:14px">A fresh start</span><h2>Your next connection starts here.</h2><p>Paste a link, give it a name, and make a little more room for your idea.</p>${btn('Create your first link','new-link','','plus')}</div>`:linksTable()}`,view==='empty'?'links':view);
}
function renderAnalytics() {
  shell(`<div class="page-title"><div><p class="eyebrow">A closer look</p><h1>Connections, in context.</h1><p>The people, places, and paths behind your clicks.</p></div>${btn('Export CSV','export-csv','light','download')}</div>${metricCards()}<div class="overview-grid">${activityChart()}${sources()}</div><section class="analytics-detail"><div class="row between"><h3>Around the world</h3><span class="muted" style="font-size:9px">Illustrative audience data</span></div><div class="country-list"><div><strong>India</strong><p>1,694 visitors · 55.1%</p><div class="source-track"><span style="width:55%"></span></div></div><div><strong>United States</strong><p>831 visitors · 27.0%</p><div class="source-track"><span style="width:27%"></span></div></div><div><strong>Everywhere else</strong><p>552 visitors · 17.9%</p><div class="source-track"><span style="width:18%"></span></div></div></div></section><section class="analytics-detail"><h3>Your best connections</h3><table class="link-table"><thead><tr><th>Link</th><th>Destination</th><th>Clicks</th><th>Ad transit</th><th>Safety</th><th>Actions</th></tr></thead><tbody>${tableRows()}</tbody></table></section>`,'analytics');
}
function renderQR() {
  const link=state.links.find(link=>link.id===state.selected)||state.links[0]||seedLinks[0];
  const size=SnipQRStudio.dimensions(state.qr);
  shell(`<div class="page-title"><div><p class="eyebrow">QR Studio</p><h1>A link worth looking at.</h1><p>Style preview for ${esc(link.title)} · All demo codes open snip-it.me.</p></div><a class="text-link" href="#links">Back to your links ${icon('back')}</a></div><div class="studio-grid qr-studio-v2"><section class="studio-stage" aria-label="Live QR preview"><span class="stage-label">FROM SCREEN TO ANYWHERE.</span><span id="qr-export-size" class="stage-size">${state.qr.size} × ${Math.round(state.qr.size*size.height/size.width)} PX</span><div class="qr-sheet" id="qr-sheet"><div id="qr-preview">${SnipQRStudio.art(state.qr)}</div></div><div id="qr-scan-status" class="qr-stage-status" role="status">Strong contrast · Scan before sharing</div><div class="qr-stage-info"><span>Sample QR → snip-it.me</span><span>4-module quiet zone preserved</span></div></section><div>${SnipQRStudio.controls(state.qr,{icon,btn})}</div></div>`,'qr');
  updateContrast();
}

function settingsSection(title,description,body) { return `<section class="settings-section"><div class="settings-section-head"><h2>${title}</h2><p>${description}</p></div><div class="settings-body">${body}</div></section>`; }
function renderAccount() {
  let body='';
  if(state.settings==='profile') body=settingsSection('Your details.','A familiar face behind the links.',`<form id="profile-form"><div class="row" style="margin-bottom:25px"><span class="avatar" style="width:46px;height:46px;font-size:15px">PG</span><div><strong style="font-size:12px">${esc(state.name)}</strong><p style="font-size:10px;margin-top:3px">Personal workspace · Joined September 2026</p></div></div><div class="form-grid"><div class="field"><label for="profile-name">Display name</label><input id="profile-name" value="${esc(state.name)}" required></div><div class="field"><label for="profile-username">Username</label><input id="profile-username" value="${esc(state.username)}" required></div><div class="field full"><div class="row between"><label for="profile-email">Email address</label>${badge('Verified')}</div><input id="profile-email" type="email" value="${esc(state.email)}" readonly><span class="hint">Used for recovery and security notifications.</span></div><div class="row between full"><button type="button" class="text-link" style="background:none;border-width:0 0 1px" data-action="change-email">Change email ${icon('up')}</button><button class="btn" type="submit">Save changes ${icon('check')}</button></div></div></form>`);
  if(state.settings==='security') body=settingsSection('Share with confidence.','Keep your account yours.',`<div class="settings-row"><div><strong>Password</strong><p>Update it regularly. Keep it somewhere safe.</p></div>${btn('Change password','change-password','light')}</div><div class="settings-row"><div class="security-session">${icon('device')}<div><strong>This browser</strong><p>Windows · Current session</p></div></div>${badge('Active now')}</div><div class="settings-row"><div><strong>Start fresh everywhere</strong><p>Sign out all devices, including this one.</p></div>${btn('Sign out everywhere','logout-all','light')}</div>`);
  if(state.settings==='developer') body=settingsSection('The key to your workflow.','Authenticate requests with X-API-Key.',`<div class="notice">${icon('key')}<span>Your key is revealed once. Keep it private and store it securely.</span></div><div class="settings-row"><div><strong>Personal API key</strong><p class="mono">snip_••••••••••••••••••••</p></div>${btn('Generate a new key','new-key','light')}</div><div class="settings-row"><div><strong>Need a starting point?</strong><p>A clear request. A short response.</p></div><a class="text-link" href="#api">API guide ${icon('up')}</a></div>`);
  if(state.settings==='preferences') body=settingsSection('The way you like it.','Small settings for a smoother day.',`<div class="settings-row"><div><strong>Security emails</strong><p>Get a note when your account details change.</p></div><button class="switch" role="switch" aria-checked="${state.preferences.securityEmails}" aria-label="Security emails" data-action="switch" data-preference="securityEmails"><span></span></button></div><div class="settings-row"><div><strong>Default ad transit</strong><p>New links start with demo ads switched off.</p></div><button class="switch" role="switch" aria-checked="${state.preferences.defaultAds}" aria-label="Default ad transit" data-action="switch" data-preference="defaultAds"><span></span></button></div><div class="settings-row"><div><strong>Timezone</strong><p>Used for analytics and link expiry.</p></div><span class="mono muted" style="font-size:10px">Asia / Kolkata</span></div>`);
  shell(`<div class="page-title"><div><p class="eyebrow">Account</p><h1>Your corner of Snip.</h1><p>A few details. A few controls. All yours.</p></div></div><div class="settings-layout"><nav class="settings-tabs" aria-label="Account settings">${[['profile','Profile'],['security','Security'],['developer','Developer'],['preferences','Preferences']].map(([id,name])=>`<button data-action="settings-tab" data-tab="${id}" class="${state.settings===id?'active':''}" aria-current="${state.settings===id?'page':'false'}">${name}</button>`).join('')}</nav><div>${body}</div></div>`,'account');
}
function renderAPI() {
  shell(`<div class="api-page"><div class="page-title"><div><p class="eyebrow">For developers</p><h1>One less thing to build.</h1><p>Short links, straight from your workflow.</p></div></div><div class="notice">${icon('shield')}<span>Every developer request requires your X-API-Key. This preview never calls the real API.</span></div><div class="api-endpoint"><span class="badge">POST</span><code>/api/shorten</code><span class="muted" style="margin-left:auto;font-size:10px">Create a short link</span></div><h2>A small request.</h2><p>Send a destination. Add an alias or expiry if you need one.</p><pre class="api-block">curl -X POST https://snip-it.me/api/shorten \
  -H "X-API-Key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com/your-big-idea"}'</pre><h2>A useful response.</h2><pre class="api-block">{
  "code": "aBigIdea",
  "short_url": "https://snip-it.me/aBigIdea",
  "original_url": "https://example.com/your-big-idea"
}</pre><div class="row between" style="margin-top:25px"><span class="muted" style="font-size:11px">Keep your API key out of public code.</span>${btn('Manage your key','manage-key','light','key')}</div></div>`,'api');
}

function authStory() { return `<aside class="auth-story"><div><p class="eyebrow">A little less link. A lot more possibility.</p><h2>Good ideas<br>deserve a<br><span class="serif">great entrance.</span></h2><p>Give yours a memorable link. And a place to see where it takes you.</p></div><div class="auth-art"><div class="long">https://your-very-long-link.com/a-big-idea</div>${icon('arrow')}<div class="short">snip-it.me/idea</div></div><div class="auth-quote"><span class="quote-icon">“</span><span>Thoughtful tools make room for the things that matter.</span></div></aside>`; }
function passwordField(id,label='Password',name='password') { return `<div class="field"><label for="${id}">${label}</label><div class="password-field"><input id="${id}" name="${name}" type="password" autocomplete="${route==='login'?'current-password':'new-password'}" required minlength="8" placeholder="At least 8 characters"><button type="button" class="icon-btn" data-action="password" data-target="${id}" aria-label="Show password">${icon('eye')}</button></div></div>`; }
function otpFields() { return `<div class="field"><label id="otp-label">Your six-digit code</label><div class="otp-boxes" role="group" aria-labelledby="otp-label">${Array.from({length:6},(_,i)=>`<input aria-label="Code digit ${i+1}" name="digit${i}" inputmode="numeric" pattern="[0-9]" maxlength="1" autocomplete="${i===0?'one-time-code':'off'}" required>`).join('')}</div><span class="hint">For this demo, use <strong>123456</strong>.</span></div>`; }
function renderAuth(view) {
  let content='';
  if(view==='login') content=`<p class="eyebrow">Welcome back</p><h1>Good to have<br>you back.</h1><p class="description">Pick up where you left off. Your links are waiting.</p><form id="login-form"><div class="field"><label for="login-email">Email or username</label><input id="login-email" name="email" autocomplete="username" placeholder="you@company.com" required></div>${passwordField('login-password')}<div class="auth-inline"><label class="check-row"><input type="checkbox" checked> Keep me signed in</label><a href="#forgot">Forgot password?</a></div><button class="btn" type="submit">Log in ${icon('arrow')}</button></form><p class="auth-bottom">A new face? <a href="#register">Make yourself at home.</a></p>`;
  if(view==='register') content=`<p class="eyebrow">Room for your ideas</p><h1>Make yourself<br>at home.</h1><p class="description">Your links, your audience, your space to keep it all together.</p><form id="register-form"><div class="field"><label for="register-name">Username</label><input id="register-name" name="username" autocomplete="username" placeholder="What should we call you?" required pattern="[A-Za-z0-9_-]{3,30}"></div><div class="field"><label for="register-email">Email address</label><input id="register-email" name="email" type="email" autocomplete="email" placeholder="you@company.com" required></div>${passwordField('register-password')}<div class="password-hints"><span id="pw-length">○ 8+ characters</span><span id="pw-letter">○ A letter</span><span id="pw-number">○ A number</span></div><button class="btn" type="submit">Create your free account ${icon('arrow')}</button><span class="hint muted" style="font-size:9px">We’ll send a code to verify your email. No email is sent in this preview.</span></form><p class="auth-bottom">Already settled in? <a href="#login">Log in.</a></p>`;
  if(view==='verify') content=`<div class="auth-symbol">${icon('mail')}</div><p class="eyebrow">One little check</p><h1>Check your inbox.</h1><p class="description">A code is on its way to<br><span class="auth-email">${esc(state.email)}</span></p><form id="verify-form">${otpFields()}<button class="btn" type="submit">Verify & continue ${icon('arrow')}</button></form><div class="auth-inline" style="margin-top:25px"><button id="resend-code" style="border:0;background:none;color:var(--green);padding:0;font-size:10px" data-action="resend">Send a new code</button><a href="#register">Change email</a></div>`;
  if(view==='success') content=`<div class="auth-symbol">${icon('check')}</div><p class="eyebrow">You’re all set</p><h1>Make good<br>connections.</h1><p class="description">Your account is ready. Here’s your personal API key—save it now. You’ll only see it once in the real app.</p><div class="reveal-key"><div class="row between" style="margin-bottom:12px"><span class="eyebrow" style="font-size:8px;color:#a7b393;margin:0">Sample API key</span><button class="icon-btn" style="color:var(--yellow)" data-action="copy-key" aria-label="Copy sample API key">${icon('copy')}</button></div><code>snip_preview_7g4x2n8k6m9p3q1</code></div><a class="btn" style="width:100%" href="#dashboard">Go to your workspace ${icon('arrow')}</a><p class="auth-bottom">A clean slate. Your next idea.</p>`;
  if(view==='forgot') content=`<div class="auth-symbol">${icon('key')}</div><p class="eyebrow">It happens</p><h1>Let’s get you<br>back in.</h1><p class="description">Tell us your email. We’ll send a recovery code if there’s a verified account for it.</p><form id="forgot-form"><div class="field"><label for="forgot-email">Email address</label><input id="forgot-email" name="email" type="email" autocomplete="email" required placeholder="you@company.com"></div><button class="btn" type="submit">Send recovery code ${icon('arrow')}</button></form><p class="auth-bottom"><a href="#login">← Back to log in</a></p>`;
  if(view==='reset') content=`<div class="auth-symbol">${icon('key')}</div><p class="eyebrow">A fresh start</p><h1>A new password.<br>Same good ideas.</h1><p class="description">Enter the recovery code for<br><span class="auth-email">${esc(state.email)}</span></p><form id="reset-form">${otpFields()}${passwordField('reset-password','New password')}<button class="btn" type="submit">Reset password ${icon('arrow')}</button></form><p class="auth-bottom"><a href="#login">← Back to log in</a></p>`;
  app.innerHTML=`${publicHeader()}<main id="page" class="auth-layout">${authStory()}<section class="auth-form-side"><div class="auth-card"><p class="demo-account-hint">Design demo. Use sample details; no account is created and no email is sent.</p>${content}</div></section></main>${footer()}`;
}
const errorCopy={
 '404':['404','A link to nowhere.','This page may have moved, or the link may have a typo. Let’s get you somewhere useful.'],
 '403':['403','This corner is private.','You don’t have access to this page. Sign in to the account that owns this link or return to your workspace.'],
 '429':['Easy.','A little breathing room.','You’ve made a few requests in a short time. Give it a moment, then try again.'],
 '500':['Oh.','Something caught a snag.','Something on our side didn’t go to plan. Your links and account are still here. Try again in a moment.'],
 '400':['Hmm.','Something doesn’t add up.','A detail in that request looks incomplete. Check your input and try again.'],
 '405':['Oops.','A different way in.','This page needs a different kind of request. Head back and use the form provided.'],
 '413':['Big.','A little too much to carry.','That request is larger than we can accept. Use a smaller file or fewer details and try again.'],
 'expired':['Time.','That moment has passed.','This short link has reached its expiry date. Ask the person who shared it for a fresh one.']
};
function renderState(view) {
  if(view==='warning') {
    app.innerHTML=`${publicHeader()}<main id="page" class="state-page"><section class="state-card danger"><div class="state-code" style="font-size:70px;display:flex;justify-content:center">${icon('alert')}</div><p class="eyebrow">A moment before you go</p><h1>This link needs<br>a second look.</h1><p>We found signs that this destination may be unsafe. Continuing could put your information or device at risk.</p><div class="state-detail"><div class="row between"><span class="mono">example-destination.com</span>${badge('Flagged','red')}</div><p style="font-size:10px;margin:14px 0 0">Reported by the link safety check. Only continue if you know and trust this destination.</p></div><div class="state-actions"><a class="btn" href="#home">Take me back ${icon('back')}</a>${btn('Continue anyway','warning-continue','light')}</div></section></main>${footer()}`;
    return;
  }
  const [code,title,description]=errorCopy[view]||errorCopy['404'];
  app.innerHTML=`${publicHeader()}<main id="page" class="state-page"><section class="state-card"><div class="state-code">${code}</div><p class="eyebrow">${view==='expired'?'Link expired':`Error ${view}`}</p><h1>${title}</h1><p>${description}</p><div class="state-actions"><a class="btn" href="#home">Back to Snip ${icon('arrow')}</a>${view==='403'?'<a class="btn light" href="#login">Log in</a>':btn('Contact us','contact','light')}</div></section></main>${footer()}`;
}
function renderTransit() {
  app.innerHTML=`${publicHeader()}<main id="page" class="transit-page"><div class="transit-heading"><span class="eyebrow muted">A short stop on the way.</span><span class="demo-tag">DEMO AD TRANSIT</span></div><h1>You’re almost there.</h1><p class="transit-sub">A brief preview before your destination. No real ad provider is connected.</p><section class="ad-sample" aria-label="Demonstration ad"><span class="eyebrow">A PLACE FOR YOUR NEXT BIG THING.</span><h2>Less noise.<br>More <span class="serif">idea.</span></h2><div class="ad-orb" aria-hidden="true"></div><small>A sample ad, by Snip.</small></section><div class="transit-destination">${icon('globe')}<div><small>You’re heading to</small><strong>github.com/cosmic-116/URL-Shortener</strong></div>${icon('up')}</div><button id="transit-button" class="btn" disabled><span id="transit-label">Continue in 10 seconds</span>${icon('arrow')}</button><div class="progress-track"><span id="transit-progress" style="width:0"></span></div><div class="transit-note"><span>Demo credits are simulated.<br>No payment or charge is involved.</span><a href="#home">Made short by Snip.</a></div></main>${footer()}`;
  let remaining=10;
  state.timer=setInterval(()=>{
    remaining--;
    $('#transit-label').textContent=remaining>0?`Continue in ${remaining} second${remaining===1?'':'s'}`:'Continue to your destination';
    $('#transit-progress').style.width=`${(10-remaining)*10}%`;
    if(remaining===0){clearInterval(state.timer);$('#transit-button').disabled=false;$('#transit-button').dataset.action='transit-continue';}
  },1000);
}
function renderEmails() {
  const type=state.emailType;
  const title={registration:'A good place to start.',reset:'Let’s get you back in.',change:'A new email. Same Snip.',security:'A small security update.'}[type];
  app.innerHTML=`${publicHeader()}<main id="page" class="email-shell"><div class="email-toolbar"><span class="eyebrow muted">In your inbox</span><select id="email-type" aria-label="Email template"><option value="registration" ${type==='registration'?'selected':''}>Registration</option><option value="reset" ${type==='reset'?'selected':''}>Password recovery</option><option value="change" ${type==='change'?'selected':''}>Email verification</option><option value="security" ${type==='security'?'selected':''}>Security alert</option></select></div><article class="email-card"><header class="email-head">${brand()}<span class="eyebrow">GOOD CONNECTIONS START HERE.</span></header><div class="email-body"><h1>${title}</h1><p>Hello Prince,<br>${type==='security'?'Your account password was recently changed. This note is here to help you keep track.':'Here’s your one-time code. Use it to '+(type==='reset'?'reset your password':type==='change'?'verify your new email':'finish creating your Snip account')+'.'}</p>${type!=='security'?'<div class="email-code">123456</div><p style="font-size:10px">This code is good for 10 minutes. Keep it to yourself; we’ll never ask you to share it.</p>':'<div class="notice">'+icon('shield')+'<span>If you made this change, you’re all set. If you didn’t, reset your password and contact us.</span></div><a class="btn" href="#forgot">Secure your account '+icon('arrow')+'</a>'}<hr class="rule"><p style="font-size:10px;margin-bottom:0">${type==='security'?'Need a hand? Contact prince.gupta@snip-it.me.':'Didn’t request this? You can safely ignore this email.'}<br>Good connections,<br>The Snip team</p></div><footer class="email-foot">Snip · snip-it.me<br>A little less link. A lot more possibility.</footer></article></main>${footer()}`;
}

function newLinkModal() {
  showModal('Make a new connection.',`<p>A destination, a memorable name, and you’re ready to share.</p><form id="new-link-form"><div class="field"><label for="new-url">Destination URL</label><input id="new-url" name="url" type="url" placeholder="https://your-big-idea.com" required autofocus></div><div class="field"><label for="new-title">Title</label><input id="new-title" name="title" placeholder="Give this link a little context" required maxlength="60"></div><div class="form-grid"><div class="field"><label for="new-alias">Custom alias</label><input id="new-alias" name="alias" placeholder="big-idea" pattern="[A-Za-z0-9_-]{1,30}"></div><div class="field"><label for="new-expiry">Expiry</label><select id="new-expiry" name="expiry"><option>Never</option><option>24 hours</option><option>7 days</option><option>30 days</option></select></div></div><label class="check-row"><input name="ads" type="checkbox"> Turn on network ad transit <span class="demo-tag">DEMO</span></label></form>`,`${btn('Cancel','close-modal','light')}<button class="btn" form="new-link-form" type="submit">Create link ${icon('arrow')}</button>`);
}
function guestLimit() {
  showModal('There’s more room inside.',`<div class="auth-symbol">${icon('link')}</div><p>You’ve used your five guest links. Your next guest slot opens in about <strong>2 hours</strong>.</p><p>A free account gives your links a home, with a dashboard, analytics, and QR Studio.</p>`,`${btn('I’ll come back','close-modal','light')}<a class="btn" href="#register" data-action="close-modal">Create free account ${icon('arrow')}</a>`);
}
function adModal(id) {
  const link=state.links.find(link=>link.id===id); if(!link)return;
  showModal('A short stop. Your call.',`<p>Choose what happens before <strong>${esc(link.title)}</strong>. All balances in this preview are simulated.</p><form id="ad-form" data-id="${id}"><div class="field"><label for="ad-mode">Ad transit</label><select id="ad-mode" name="mode"><option value="off" ${link.ad==='off'?'selected':''}>Off — straight to the destination</option><option value="network" ${link.ad==='network'?'selected':''}>Network demo — simulated +$0.02</option><option value="custom" ${link.ad==='custom'?'selected':''}>Custom demo — simulated -$0.01</option></select></div><div id="custom-ad-fields" ${link.ad!=='custom'?'hidden':''}><div class="field"><label for="ad-url">Your campaign URL</label><input id="ad-url" type="url" name="url" placeholder="https://your-campaign.com"></div><div class="field" style="margin-top:15px"><label for="ad-heading">Headline</label><input id="ad-heading" name="headline" placeholder="Your next big thing" maxlength="70"></div></div><div class="notice" style="margin-bottom:0">${icon('clock')}<span>Visitors wait 10 seconds before continuing. No real revenue, payout, or charge is connected.</span></div></form>`,`${btn('Cancel','close-modal','light')}<button class="btn" form="ad-form" type="submit">Save settings ${icon('check')}</button>`);
}
function updateQR() {
  if(!$('#qr-preview'))return;
  $('#qr-preview').innerHTML=SnipQRStudio.art(state.qr);
  $('#qr-fg-label').textContent=state.qr.fg.toUpperCase();
  $('#qr-bg-label').textContent=state.qr.bg.toUpperCase();
  const size=SnipQRStudio.dimensions(state.qr);
  $('#qr-export-size').textContent=`${state.qr.size} × ${Math.round(state.qr.size*size.height/size.width)} PX`;
  updateContrast();
}
function updateContrast() {
  if(!$('#contrast-note'))return;
  const ratio=SnipQRStudio.contrast(state.qr),safe=ratio>=4.5;
  $('#contrast-note').hidden=safe;
  const status=$('#qr-scan-status');status.classList.toggle('warn',!safe);
  status.textContent=safe?`Contrast ${ratio.toFixed(1)}:1 · Scan before sharing`:'Low contrast · Adjust your colors';
  $$('[data-action="download-png"], [data-action="download-svg"]').forEach(button=>{button.disabled=!safe;});
}

function downloadFile(blob,name) {
  const url=URL.createObjectURL(blob),anchor=document.createElement('a');
  anchor.href=url;anchor.download=name;document.body.append(anchor);anchor.click();anchor.remove();
  setTimeout(()=>URL.revokeObjectURL(url),1000);toast('Your sample download is ready.');
}
function downloadQR(type) {
  if(SnipQRStudio.contrast(state.qr)<4.5){toast('Increase contrast before downloading.');return;}
  const config={...state.qr},svg=SnipQRStudio.art(config);
  if(type==='svg'){downloadFile(new Blob([svg],{type:'image/svg+xml'}),'snip-design-sample.svg');return;}
  const source=URL.createObjectURL(new Blob([svg],{type:'image/svg+xml'})),image=new Image();
  image.onload=()=>{
    try {
      const size=SnipQRStudio.dimensions(config),canvas=document.createElement('canvas');
      canvas.width=config.size;canvas.height=Math.round(config.size*size.height/size.width);
      const context=canvas.getContext('2d');context.drawImage(image,0,0,canvas.width,canvas.height);
      canvas.toBlob(blob=>{if(blob)downloadFile(blob,'snip-design-sample.png');else toast('Could not export. Try SVG.');},'image/png');
    } catch(error){toast('Could not export. Try SVG.');}
    finally {URL.revokeObjectURL(source);}
  };
  image.onerror=()=>{URL.revokeObjectURL(source);toast('Could not export. Try SVG.');};image.src=source;
}

function validatePreviewURL(raw) {
  try{const url=new URL(raw);return ['http:','https:'].includes(url.protocol);}catch{return false;}
}
function formError(form,message) {
  $('.form-error',form)?.remove();
  const error=document.createElement('div');error.className='form-error';error.setAttribute('role','alert');error.textContent=message;form.prepend(error);
}
function routeTo(id){location.hash=id;}
function render() {
  clearInterval(state.timer);$('#modal').close();
  route=location.hash.slice(1)||'home';
  $('#preview-menu').hidden=true;$('#preview-toggle').setAttribute('aria-expanded','false');
  document.title=`Snip demo · ${screens.find(([id])=>id===route)?.[1]||'Preview'}`;
  if(route==='home'||route==='guest-limit')renderHome();
  else if(['dashboard','links','empty'].includes(route))renderDashboard(route);
  else if(route==='analytics')renderAnalytics();
  else if(route==='qr')renderQR();
  else if(route==='account')renderAccount();
  else if(route==='api')renderAPI();
  else if(['login','register','verify','success','forgot','reset'].includes(route))renderAuth(route);
  else if(route==='transit')renderTransit();
  else if(route==='emails')renderEmails();
  else renderState(route);
  $('#screen-list').innerHTML=screens.map(([id,label])=>`<a href="#${id}" class="${route===id?'active':''}" ${route===id?'aria-current="page"':''}>${label}</a>`).join('');
  window.scrollTo({top:0,left:0,behavior:'instant'});
  if(route==='guest-limit')guestLimit();
}

document.addEventListener('click',event=>{
  if(event.target.closest('.skip-link')){event.preventDefault();const page=$('#page');page.tabIndex=-1;page.focus();page.scrollIntoView();return;}
  const target=event.target.closest('[data-action]');
  if(!target)return;
  const action=target.dataset.action,id=target.dataset.id;
  if(target.tagName==='A'&&!['close-modal'].includes(action))event.preventDefault();
  if(action==='close-modal')$('#modal').close();
  if(action==='menu')$('.app-shell').classList.toggle('menu-open');
  if(action==='advanced'){const panel=$('#advanced-home');panel.hidden=!panel.hidden;target.setAttribute('aria-expanded',String(!panel.hidden));target.innerHTML=`Make it yours ${icon(panel.hidden?'plus':'close')}`;}
  if(action==='new-link')newLinkModal();
  if(action==='copy')copy(`https://snip-it.me/${target.dataset.code}`);
  if(action==='clear-search'){state.query='';$('#link-search').value='';$('#link-rows').innerHTML=tableRows();$('#link-count').textContent=linkCountText();}
  if(action==='guest-qr'){showModal('A link for the real world.',`<p>Guests can preview and download a basic QR. Create an account to style the links you own.</p><div class="qr-modal-art">${qrSvg()}</div><p style="font-size:10px;text-align:center">This sample QR opens snip-it.me.</p>`,`${btn('Download PNG','guest-download','','download')}`);}
  if(action==='guest-download'){const original={...state.qr};state.qr={...SnipQRStudio.defaults};downloadQR('png');state.qr=original;}
  if(action==='link-qr'){state.selected=id;routeTo('qr');}
  if(action==='ad-settings')adModal(id);
  if(action==='delete'){const link=state.links.find(item=>item.id===id);if(link)showModal('This connection ends here.',`<p>Delete <strong>${esc(link.title)}</strong>? In the real app, its short link will stop working.</p><p style="font-size:10px">You’re only deleting sample data in this preview.</p>`,`${btn('Keep it','close-modal','light')}<button class="btn danger" data-action="confirm-delete" data-id="${id}">Delete link ${icon('trash')}</button>`);}
  if(action==='confirm-delete'){state.links=state.links.filter(item=>item.id!==id);$('#modal').close();render();toast('Sample link deleted.');}
  if(action==='qr-preset'){const presets={classic:['#171b18','#fffefa'],forest:['#245840','#eef1e2'],acid:['#171b18','#e5f45a'],night:['#e5f45a','#171b18']};const [fg,bg]=presets[target.dataset.preset];Object.assign(state.qr,{fg,bg,preset:target.dataset.preset});renderQR();}
  if(action==='qr-shape'){state.qr.shape=target.dataset.shape;$$('.qr-shape-options button').forEach(button=>{button.classList.toggle('active',button===target);button.setAttribute('aria-pressed',String(button===target));});updateQR();}
  if(action==='qr-reset'){state.qr={...SnipQRStudio.defaults};renderQR();toast('Back to a clean canvas.');}
  if(action==='qr-remove-logo'){state.qr.logo='';renderQR();toast('Logo removed.');}
  if(action==='qr-save'){try{const {logo,...style}=state.qr;localStorage.setItem('snip-demo-qr-style',JSON.stringify(style));toast('Style saved on this device. Logos stay out of saved presets.');}catch(error){toast('Your browser could not save this style.');}}
  if(action==='qr-load'){try{state.qr=SnipQRStudio.savedStyle(JSON.parse(localStorage.getItem('snip-demo-qr-style')));renderQR();toast('Your saved style, ready to use.');}catch(error){toast('No saved style yet. Save one first.');}}
  if(action==='download-png')downloadQR('png');
  if(action==='download-svg')downloadQR('svg');
  if(action==='copy-embed'){const link=state.links.find(item=>item.id===state.selected)||seedLinks[0];copy(`<img src="https://snip-it.me/qr/${link.code}" alt="Scan to visit ${link.title}" />`);}
  if(action==='password'){const input=$(`#${target.dataset.target}`),show=input.type==='password';input.type=show?'text':'password';target.setAttribute('aria-label',show?'Hide password':'Show password');}
  if(action==='resend'){let left=60;target.disabled=true;target.textContent=`New code in ${left}s`;toast('Sample code is still 123456. No email was sent.');state.timer=setInterval(()=>{left--;target.textContent=left?`New code in ${left}s`:'Send a new code';if(!left){clearInterval(state.timer);target.disabled=false;}},1000);}
  if(action==='settings-tab'){state.settings=target.dataset.tab;renderAccount();}
  if(action==='switch'){const checked=target.getAttribute('aria-checked')!=='true';target.setAttribute('aria-checked',String(checked));state.preferences[target.dataset.preference]=checked;toast('Sample preference saved.');}
  if(action==='change-email')showModal('A new inbox.',`<p>We’ll verify the new address before updating your account. This preview sends no email.</p><form id="change-email-form"><div class="field"><label for="new-email">New email</label><input id="new-email" name="email" type="email" required placeholder="you@company.com"></div>${passwordField('email-password','Current password')}</form>`,`${btn('Cancel','close-modal','light')}<button class="btn" form="change-email-form">Send verification code ${icon('arrow')}</button>`);
  if(action==='change-password')showModal('A fresh password.',`<p>Updating your password signs out your other sessions.</p><form id="change-password-form">${passwordField('current-password','Current password','current_password')}${passwordField('new-password','New password','new_password')}</form>`,`${btn('Cancel','close-modal','light')}<button class="btn" form="change-password-form">Update password ${icon('check')}</button>`);
  if(action==='logout-all')showModal('Start fresh everywhere?',`<p>In the real app, this signs you out of every browser and device. You’ll return to the login page.</p>`,`${btn('Stay here','close-modal','light')}${btn('Sign out everywhere','confirm-logout','','logout')}`);
  if(action==='confirm-logout'){routeTo('login');toast('Sample sessions cleared.');}
  if(action==='new-key')showModal('A new key. A clean slate.',`<p>Your previous API key will stop working. Update any tools that use it.</p><form id="new-key-form">${passwordField('key-password','Current password')}</form>`,`${btn('Cancel','close-modal','light')}<button class="btn" form="new-key-form">Generate key ${icon('key')}</button>`);
  if(action==='copy-key')copy('snip_preview_7g4x2n8k6m9p3q1');
  if(action==='manage-key'){state.settings='developer';routeTo('account');}
  if(action==='chart'){state.chart=target.dataset.period;$$('[data-action="chart"]').forEach(button=>{button.classList.toggle('active',button===target);button.setAttribute('aria-pressed',String(button===target));});const labels={week:['FRI 02','SAT 03','SUN 04','MON 05','TUE 06','WED 07','THU 08'],month:['SEP 09','SEP 14','SEP 19','SEP 24','SEP 29','OCT 04','OCT 08'],year:['NOV','JAN','MAR','MAY','JUL','SEP','OCT']};$$('.chart-labels span').forEach((item,i)=>item.textContent=labels[state.chart][i]);$('#chart-sub').textContent=state.chart==='week'?'A good week for your ideas.':state.chart==='month'?'A month of making connections.':'A year of ideas going places.';$('#chart-line').style.transform=state.chart==='month'?'translateY(10px)':state.chart==='year'?'scaleY(.8)':'none';}
  if(action==='export-csv'){const rows=['Title,Short link,Clicks',...state.links.map(link=>`"${link.title.replaceAll('"','""')}",https://snip-it.me/${link.code},${link.clicks}`)];downloadFile(new Blob([rows.join('\n')],{type:'text/csv'}),'snip-sample-analytics.csv');}
  if(action==='contact')location.href='mailto:prince.gupta@snip-it.me';
  if(action==='transit-continue'){toast('Destination reached in the sample.');routeTo('dashboard');}
  if(action==='warning-continue')showModal('Only if you trust it.',`<p>This is a demonstration warning. The preview won’t open an unsafe destination.</p>`,`${btn('Back to Snip','close-warning','','arrow')}`);
  if(action==='close-warning')routeTo('home');
  if(action==='visit-sample')toast('Sample short link. No destination was opened.');
});

document.addEventListener('submit',async event=>{
  const form=event.target;if(!form.id)return;event.preventDefault();
  const data=new FormData(form);
  if(form.id==='home-shorten'){
    if(!validatePreviewURL(data.get('url'))){toast('Use a complete http:// or https:// URL.');return;}
    if(!state.guests){guestLimit();return;}
    const submitButton=$('button[type="submit"]',form);
    submitButton.disabled=true;submitButton.textContent='Snipping…';
    try { await window.SnipCut?.play(data.get('url'),`snip-it.me/${data.get('alias')||'aBigIdea'}`); } catch(error) { /* Always reveal the result. */ }
    if(!form.isConnected)return;
    submitButton.disabled=false;submitButton.innerHTML=`Snip it ${icon('scissors')}`;
    state.guests--;$('#guest-count').textContent=state.guests;
    const code=data.get('alias')||'aBigIdea';
    $('#home-result').innerHTML=`<section class="result-strip"><div><p class="eyebrow" style="color:var(--green)">Short, sweet, ready to share.</p><div class="short-url mono">snip-it.me/${esc(code)}</div><span class="muted" style="font-size:9px">Demo link · ${esc(data.get('url'))}</span></div><div class="result-actions"><button class="btn" data-action="copy" data-code="${esc(code)}">Copy link ${icon('copy')}</button>${btn('QR','guest-qr','light','qr')}${btn('Visit','visit-sample','light','up')}</div></section>`;
    toast('Your sample link is ready.');
  }
  if(form.id==='new-link-form'){
    if(!validatePreviewURL(data.get('url')))return formError(form,'Use a complete http:// or https:// URL.');
    const code=data.get('alias')||`idea${state.links.length+1}`;
    if(state.links.some(link=>link.code.toLowerCase()===code.toLowerCase()))return formError(form,'That alias is already in your sample library. Try another.');
    state.links.unshift({id:`sample${Date.now()}`,title:data.get('title'),code,url:data.get('url'),clicks:0,date:'Oct 08, 2026',ad:data.get('ads')?'network':'off',safe:'unchecked',mark:'↗'});
    $('#modal').close();if(route==='empty')routeTo('links');else render();toast('A new sample connection, ready to share.');
  }
  if(form.id==='login-form'){state.signedIn=true;routeTo('dashboard');toast('Welcome to the sample workspace.');}
  if(form.id==='register-form'){
    const password=data.get('password');if(!/[A-Za-z]/.test(password)||!/[0-9]/.test(password))return formError(form,'Add at least one letter and one number to your password.');
    state.email=data.get('email');state.verifyPurpose='register';routeTo('verify');
  }
  if(form.id==='verify-form'||form.id==='reset-form'){
    const code=Array.from({length:6},(_,i)=>data.get(`digit${i}`)).join('');if(code!=='123456')return formError(form,'For the preview, enter 123456.');
    if(form.id==='reset-form'&&(!/[A-Za-z]/.test(data.get('password'))||!/[0-9]/.test(data.get('password'))))return formError(form,'Include at least one letter and one number.');
    routeTo(form.id==='verify-form'?(state.verifyPurpose==='change'?'account':'success'):'login');
    if(form.id==='reset-form')toast('Sample password reset. No real account was changed.');
    else if(state.verifyPurpose==='change')toast('Sample email verified.');
  }
  if(form.id==='forgot-form'){state.email=data.get('email');routeTo('reset');}
  if(form.id==='ad-form'){const link=state.links.find(link=>link.id===form.dataset.id);if(link)link.ad=data.get('mode');$('#modal').close();render();toast('Sample ad settings saved.');}
  if(form.id==='profile-form'){state.name=$('#profile-name').value;state.username=$('#profile-username').value;renderAccount();toast('Sample profile saved.');}
  if(form.id==='change-email-form'){state.email=data.get('email');state.verifyPurpose='change';routeTo('verify');}
  if(form.id==='change-password-form'){
    const password=data.get('new_password');
    if(!/[A-Za-z]/.test(password)||!/[0-9]/.test(password))return formError(form,'Include at least one letter and one number.');
    $('#modal').close();toast('Sample password updated. No real account changed.');
  }
  if(form.id==='new-key-form')showModal('Keep this one somewhere safe.',`<p>Here’s your new sample key. The real key is shown only once.</p><div class="reveal-key"><code>snip_preview_7g4x2n8k6m9p3q1</code></div>`,`${btn('Copy key','copy-key','light','copy')}${btn('I’ve saved it','close-modal','','check')}`);
});
document.addEventListener('input',event=>{
  const input=event.target;
  if(input.id==='link-search'){state.query=input.value;$('#link-rows').innerHTML=tableRows();$('#link-count').textContent=linkCountText();}
  if(input.id==='qr-foreground'||input.id==='qr-background'){state.qr[input.id==='qr-foreground'?'fg':'bg']=input.value;state.qr.preset='custom';$$('.preset').forEach(button=>{button.classList.remove('active');button.setAttribute('aria-pressed','false');});updateQR();}
  if(input.id==='qr-caption-input'){state.qr.caption=input.value;updateQR();}
  if(input.id==='qr-gradient-color'){state.qr.fg2=input.value;updateQR();}
  if(input.id==='register-password'){[['pw-length',input.value.length>=8,'8+ characters'],['pw-letter',/[A-Za-z]/.test(input.value),'A letter'],['pw-number',/[0-9]/.test(input.value),'A number']].forEach(([id,met,text])=>{$(`#${id}`).textContent=`${met?'✓':'○'} ${text}`;$(`#${id}`).classList.toggle('met',met);});}
  if(input.closest('.otp-boxes')){input.value=input.value.replace(/\D/g,'').slice(0,1);if(input.value)input.nextElementSibling?.focus();}
});
document.addEventListener('paste',event=>{
  if(!event.target.closest('.otp-boxes'))return;
  const digits=event.clipboardData.getData('text').replace(/\D/g,'').slice(0,6);if(!digits)return;
  event.preventDefault();const boxes=$$('input',event.target.closest('.otp-boxes'));boxes.forEach((input,i)=>input.value=digits[i]||'');boxes[Math.min(digits.length,6)-1].focus();
});
document.addEventListener('keydown',event=>{
  if(event.target.closest('.otp-boxes')&&event.key==='Backspace'&&!event.target.value)event.target.previousElementSibling?.focus();
  if(event.key==='Escape'){$('#preview-menu').hidden=true;$('#preview-toggle').setAttribute('aria-expanded','false');$('.app-shell')?.classList.remove('menu-open');}
});
document.addEventListener('change',async event=>{
  const field=event.target;
  if(field.id==='qr-logo'){
    try{const logo=await SnipQRStudio.readLogo(field.files[0]);state.qr.logo=logo;if(route==='qr')renderQR();toast('Your logo is ready. It stays in this browser.');}catch(error){toast(error.message);field.value='';}
  }
  if(field.id==='qr-eyes'){state.qr.eyes=field.value;updateQR();}
  if(field.id==='qr-frame'){state.qr.frame=field.value;$('#qr-caption-field').hidden=field.value==='plain';updateQR();}
  if(field.id==='qr-gradient'){state.qr.gradient=field.checked;$('#qr-gradient-field').hidden=!field.checked;updateQR();}
  if(field.id==='qr-size'){state.qr.size=Number(field.value);updateQR();}
  if(event.target.id==='link-sort'){state.sort=event.target.value;$('#link-rows').innerHTML=tableRows();}
  if(event.target.id==='ad-mode')$('#custom-ad-fields').hidden=event.target.value!=='custom';
  if(event.target.id==='email-type'){state.emailType=event.target.value;renderEmails();}
});
document.addEventListener('click',event=>{
  const scroll=event.target.closest('[data-scroll]');if(scroll&&route==='home'){event.preventDefault();$('#features').scrollIntoView({behavior:matchMedia('(prefers-reduced-motion:reduce)').matches?'instant':'smooth'});}
  if(!event.target.closest('.preview-dock')){$('#preview-menu').hidden=true;$('#preview-toggle').setAttribute('aria-expanded','false');}
});
$('#preview-toggle').addEventListener('click',()=>{const menu=$('#preview-menu');menu.hidden=!menu.hidden;$('#preview-toggle').setAttribute('aria-expanded',String(!menu.hidden));});
$('#reset-demo').addEventListener('click',()=>{state.links=structuredClone(seedLinks);state.guests=5;state.query='';state.sort='newest';state.name='Prince Gupta';state.username='princegupta';state.email='prince.gupta@snip-it.me';state.preferences={securityEmails:true,defaultAds:false};state.qr={...SnipQRStudio.defaults};render();toast('A clean slate. Sample data reset.');});
$('#modal').addEventListener('click',event=>{if(event.target===$('#modal'))$('#modal').close();});
window.addEventListener('hashchange',render);
render();

// The standalone preview can still return to the real website.
if(!location.pathname.startsWith('/design/demo/'))document.getElementById('back-classic').href='https://snip-it.me/';
