/* Shared Dashboard JavaScript */
(function () {
  const c = document.getElementById('cursor');
  const r = document.getElementById('cursor-ring');
  let mx = 0,
    my = 0,
    rx = 0,
    ry = 0;

  document.addEventListener('mousemove', (e) => {
    mx = e.clientX;
    my = e.clientY;
    c.style.left = mx + 'px';
    c.style.top = my + 'px';
  });

  (function loop() {
    rx += (mx - rx) * 0.15;
    ry += (my - ry) * 0.15;
    r.style.left = rx + 'px';
    r.style.top = ry + 'px';
    requestAnimationFrame(loop);
  })();

  document.querySelectorAll('a,button,.kpi,.card').forEach((el) => {
    el.addEventListener('mouseenter', () => {
      c.style.width = '14px';
      c.style.height = '14px';
      r.style.width = '56px';
      r.style.height = '56px';
      r.style.borderColor = 'rgba(0,212,245,.7)';
    });

    el.addEventListener('mouseleave', () => {
      c.style.width = '8px';
      c.style.height = '8px';
      r.style.width = '36px';
      r.style.height = '36px';
      r.style.borderColor = 'rgba(0,212,245,.4)';
    });
  });
})();

window.addEventListener('load', () => {
  gsap.from('.page-hdr', {
    opacity: 0,
    y: 20,
    duration: 0.8,
    ease: 'power3.out'
  });
});
