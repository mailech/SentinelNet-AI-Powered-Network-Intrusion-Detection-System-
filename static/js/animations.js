// PARTICLES
(function () {
  const c = document.getElementById('particles');
  const ctx = c.getContext('2d');
  let W, H, pts = [];

  function resize() {
    W = c.width = innerWidth;
    H = c.height = innerHeight;
  }

  resize();
  window.addEventListener('resize', resize);

  for (let i = 0; i < 80; i++) {
    pts.push({
      x: Math.random() * 1920,
      y: Math.random() * 1080,
      vx: (Math.random() - 0.5) * 0.3,
      vy: (Math.random() - 0.5) * 0.3,
      r: Math.random() * 1.5 + 0.5,
      o: Math.random() * 0.5 + 0.1
    });
  }

  function draw() {
    ctx.clearRect(0, 0, W, H);

    pts.forEach((p) => {
      p.x += p.vx;
      p.y += p.vy;
      if (p.x < 0) p.x = W;
      if (p.x > W) p.x = 0;
      if (p.y < 0) p.y = H;
      if (p.y > H) p.y = 0;

      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(0,212,245,${p.o})`;
      ctx.fill();
    });

    pts.forEach((a, i) =>
      pts.slice(i + 1).forEach((b) => {
        const d = Math.hypot(a.x - b.x, a.y - b.y);
        if (d < 120) {
          ctx.beginPath();
          ctx.moveTo(a.x, a.y);
          ctx.lineTo(b.x, b.y);
          ctx.strokeStyle = `rgba(0,212,245,${(1 - d / 120) * 0.07})`;
          ctx.stroke();
        }
      })
    );

    requestAnimationFrame(draw);
  }

  draw();
})();

// CURSOR
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

  document.querySelectorAll('a,button,.btn,.pip-card,.atk-row,.res-card,.tech-pill').forEach((el) => {
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

// GSAP ANIMATIONS
window.addEventListener('load', function () {
  gsap.registerPlugin(ScrollTrigger);

  // Word animations
  gsap.to('.hero-title .word', {
    y: 0,
    stagger: 0.12,
    duration: 1,
    ease: 'expo.out',
    delay: 0.2
  });

  // Hero elements
  gsap.to(
    ['#hero-ey', '#hero-s', '#hero-c', '#scroll-ind'],
    {
      opacity: 1,
      y: 0,
      stagger: 0.12,
      duration: 0.8,
      ease: 'power3.out',
      delay: 0.65
    }
  );

  // Scroll reveal animations
  document.querySelectorAll('[data-reveal]').forEach((el) => {
    gsap.from(el, {
      scrollTrigger: {
        trigger: el,
        start: 'top 88%',
        once: true
      },
      opacity: 0,
      y: 30,
      duration: 0.8,
      ease: 'power3.out'
    });
  });
});

// Scroll event for navbar
window.addEventListener('scroll', () => {
  document.getElementById('navbar').classList.toggle('scrolled', scrollY > 40);
});
