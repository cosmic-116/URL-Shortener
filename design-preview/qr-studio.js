/* Client-only QR styling. The encoded sample stays https://snip-it.me. */
(() => {
  const defaults = {fg:'#171b18',bg:'#fffefa',fg2:'#245840',shape:'square',preset:'classic',eyes:'square',frame:'plain',caption:'SCAN FOR SOMETHING GOOD',gradient:false,size:1200,logo:''};
  const escapeXML = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  function dimensions(config) { return {width:320,height:config.frame==='poster'?410:config.frame==='caption'?370:320}; }
  function contrast(config) {
    const lum = hex => {const rgb=[1,3,5].map(i=>parseInt(hex.slice(i,i+2),16)/255).map(n=>n<=.04045?n/12.92:((n+.055)/1.055)**2.4);return rgb[0]*.2126+rgb[1]*.7152+rgb[2]*.0722;};
    const ratio = color => {const a=lum(color),b=lum(config.bg);return (Math.max(a,b)+.05)/(Math.min(a,b)+.05);};
    return Math.min(ratio(config.fg),config.gradient?ratio(config.fg2):Infinity);
  }
  function art(raw) {
    const c={...defaults,...raw},matrix=window.SNIP_QR_MATRIX,n=matrix.length,quiet=4,side=n+quiet*2;
    const {width,height}=dimensions(c);
    const isFinder=(x,y)=>(x<7&&y<7)||(x>=n-7&&y<7)||(x<7&&y>=n-7);
    const fg=c.gradient?'url(#snip-qr-gradient)':c.fg;
    let cells='';
    matrix.forEach((row,y)=>row.forEach((cell,x)=>{
      if(!cell || (c.eyes==='soft'&&isFinder(x,y)))return;
      if(c.shape==='dots'&&!isFinder(x,y))cells+=`<circle cx="${x+quiet+.5}" cy="${y+quiet+.5}" r=".47"/>`;
      else cells+=`<rect x="${x+quiet}" y="${y+quiet}" width="1" height="1"${c.shape==='rounded'&&!isFinder(x,y)?' rx=".22"':''}/>`;
    }));
    let eyes='';
    if(c.eyes==='soft')[[quiet,quiet],[n-7+quiet,quiet],[quiet,n-7+quiet]].forEach(([x,y])=>{
      eyes+=`<rect x="${x}" y="${y}" width="7" height="7" rx="1.1" fill="${fg}"/><rect x="${x+1}" y="${y+1}" width="5" height="5" rx=".55" fill="${c.bg}"/><rect x="${x+2}" y="${y+2}" width="3" height="3" rx=".35" fill="${fg}"/>`;
    });
    const logo=c.logo&&/^data:image\/png;base64,[A-Za-z0-9+/=]+$/.test(c.logo)?`<rect x="${side/2-4}" y="${side/2-4}" width="8" height="8" rx="1" fill="${c.bg}"/><image href="${c.logo}" x="${side/2-3}" y="${side/2-3}" width="6" height="6" preserveAspectRatio="xMidYMid meet"/>`:'';
    const caption=escapeXML(c.caption.trim().slice(0,32)||'SCAN ME');
    const plate=c.frame==='poster'?c.fg:c.bg;
    const frame=c.frame==='plain'?'':`<text x="160" y="${c.frame==='poster'?360:339}" text-anchor="middle" font-family="Arial,Helvetica,sans-serif" font-size="${c.frame==='poster'?14:11}" font-weight="700" letter-spacing="1" fill="${c.frame==='poster'?c.bg:c.fg}">${caption}</text>${c.frame==='poster'?`<text x="160" y="385" text-anchor="middle" font-family="Arial,Helvetica,sans-serif" font-size="9" letter-spacing="2" fill="${c.bg}">SNIP-IT.ME</text>`:''}`;
    return `<svg class="qr-svg" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" width="${width}" height="${height}" role="img" aria-label="Sample QR code for snip-it.me"><defs><linearGradient id="snip-qr-gradient" x1="0" y1="0" x2="1" y2="1"><stop stop-color="${c.fg}"/><stop offset="1" stop-color="${c.fg2}"/></linearGradient></defs><rect width="${width}" height="${height}" rx="${c.frame==='poster'?9:0}" fill="${plate}"/><svg x="${c.frame==='poster'?14:0}" y="${c.frame==='poster'?14:0}" width="${c.frame==='poster'?292:320}" height="${c.frame==='poster'?292:320}" viewBox="0 0 ${side} ${side}"><rect width="${side}" height="${side}" rx="${c.frame==='poster'?1:0}" fill="${c.bg}"/><g fill="${fg}">${cells}</g>${eyes}${logo}</svg>${frame}</svg>`;
  }
  function controls(c,{icon,btn}) {
    const field=(label,id,options,value)=>`<div class="field"><label for="${id}">${label}</label><select id="${id}">${options.map(([val,text])=>`<option value="${val}" ${String(value)===String(val)?'selected':''}>${text}</option>`).join('')}</select></div>`;
    return `<div class="studio-controls"><section class="control-section"><div class="row between"><h3>Choose a starting point.</h3><button class="icon-btn" data-action="qr-reset" aria-label="Reset QR design">${icon('back')}</button></div><div class="preset-grid">${[['classic','Classic','#171b18','#fffefa'],['forest','Forest','#245840','#eef1e2'],['acid','Acid','#171b18','#e5f45a'],['night','Night','#e5f45a','#171b18']].map(([id,name,foreground,background])=>`<button class="preset ${c.preset===id?'active':''}" data-action="qr-preset" data-preset="${id}" aria-pressed="${c.preset===id}"><span class="preset-swatch" style="background:${background};box-shadow:inset 0 0 0 7px ${foreground}"></span>${name}</button>`).join('')}</div></section><section class="control-section"><h3>Shape the details.</h3><div class="qr-shape-options">${[['square','Square'],['rounded','Soft'],['dots','Dots']].map(([id,label])=>`<button data-action="qr-shape" data-shape="${id}" aria-pressed="${c.shape===id}"><span class="shape-example ${id==='rounded'?'round':id==='dots'?'dots':''}"></span>${label}</button>`).join('')}</div><div class="qr-select-row">${field('Finder corners','qr-eyes',[['square','Square'],['soft','Rounded']],c.eyes)}${field('Frame','qr-frame',[['plain','QR only'],['caption','Caption'],['poster','Print card']],c.frame)}</div></section><section class="control-section"><h3>Make it feel like you.</h3><div class="color-fields"><label class="color-control"><input id="qr-foreground" type="color" value="${c.fg}" aria-label="QR pattern color"><span id="qr-fg-label">${c.fg.toUpperCase()}</span></label><label class="color-control"><input id="qr-background" type="color" value="${c.bg}" aria-label="QR background color"><span id="qr-bg-label">${c.bg.toUpperCase()}</span></label></div><div class="row between color-labels"><span>Pattern</span><span>Background</span></div><label class="check-row"><input id="qr-gradient" type="checkbox" ${c.gradient?'checked':''}> Blend a second color</label><div id="qr-gradient-field" class="field" ${c.gradient?'':'hidden'} style="margin-top:14px"><label for="qr-gradient-color">Second pattern color</label><input id="qr-gradient-color" type="color" value="${c.fg2}"></div><div id="qr-caption-field" class="field" ${c.frame==='plain'?'hidden':''} style="margin-top:16px"><label for="qr-caption-input">Caption</label><input id="qr-caption-input" maxlength="32" value="${escapeXML(c.caption)}" placeholder="SCAN FOR SOMETHING GOOD"></div><p id="contrast-note" class="contrast-note" hidden>These colors are too close for reliable scanning. Increase contrast before downloading.</p></section><section class="control-section"><h3>Your mark, right in the middle.</h3><div class="qr-logo-tools">${c.logo?`<img class="qr-logo-preview" src="${c.logo}" alt="Uploaded QR logo">`:''}<label class="btn light qr-upload">${icon('plus')} ${c.logo?'Replace logo':'Add a logo'}<input id="qr-logo" type="file" accept="image/png,image/jpeg,image/webp" aria-label="Upload QR logo"></label>${c.logo?btn('Remove','qr-remove-logo','light'):''}</div><p class="qr-helper">PNG, JPEG or WebP, up to 1 MB. Your image stays in this browser. Always scan a test, especially with a logo.</p></section><section class="control-section"><h3>Ready when you are.</h3>${field('PNG width','qr-size',[[600,'600 px · screens'],[1200,'1200 px · everyday print'],[2400,'2400 px · larger print']],c.size)}<div class="export-row">${btn('Download PNG','download-png','','download')}${btn('SVG','download-svg','light','download')}</div><div class="qr-action-row"><button data-action="qr-save">Save this style</button><button data-action="qr-load">Load saved style</button></div><p class="qr-helper">This demo QR opens snip-it.me. SVG scales to any size. Scan your export before sharing.</p></section></div>`;
  }
  async function readLogo(file) {
    if(!file || !['image/png','image/jpeg','image/webp'].includes(file.type))throw new Error('Choose a PNG, JPEG, or WebP image.');
    if(file.size>1024*1024)throw new Error('Choose an image smaller than 1 MB.');
    const url=URL.createObjectURL(file);
    try {
      const image=new Image();image.src=url;await image.decode();
      if(!image.width||!image.height||image.width>4096||image.height>4096)throw new Error('Use a logo no larger than 4096 × 4096 pixels.');
      const canvas=document.createElement('canvas');canvas.width=canvas.height=256;
      const ctx=canvas.getContext('2d'),scale=Math.min(256/image.width,256/image.height);
      ctx.drawImage(image,(256-image.width*scale)/2,(256-image.height*scale)/2,image.width*scale,image.height*scale);
      return canvas.toDataURL('image/png');
    } catch(error) {throw new Error(error.message==='Use a logo no larger than 4096 × 4096 pixels.'?error.message:'That image could not be opened. Try a different file.');}
    finally {URL.revokeObjectURL(url);}
  }
  function savedStyle(raw) {
    if(!raw||typeof raw!=='object')throw new Error('No saved style yet. Save one first.');
    const style={...defaults};
    ['fg','bg','fg2'].forEach(key=>{if(/^#[0-9a-f]{6}$/i.test(raw[key]))style[key]=raw[key];});
    for(const [key,choices] of Object.entries({shape:['square','rounded','dots'],eyes:['square','soft'],frame:['plain','caption','poster']}))if(choices.includes(raw[key]))style[key]=raw[key];
    style.caption=typeof raw.caption==='string'?raw.caption.slice(0,32):defaults.caption;
    style.size=[600,1200,2400].includes(raw.size)?raw.size:1200;style.gradient=raw.gradient===true;style.preset='custom';return style;
  }
  window.SnipQRStudio={defaults,dimensions,contrast,art,controls,readLogo,savedStyle};
})();
