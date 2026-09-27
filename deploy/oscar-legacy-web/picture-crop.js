// The geometry of the picture editor: which part of the uploaded picture
// becomes the buddy icon, from the zoom and the point the user centred on.
//
// The picture page and the server use the very same function: the server
// puts its source into the page's script (pictureEditorScript in server.js),
// so the preview and the file the client gets are cut by one formula. It is
// written in the JavaScript the client's embedded IE understands for that
// reason: var, function, no arrows.
//
//   w, h    the size of the picture on the server (its working copy)
//   z       the zoom: 1 is the whole picture cut to the frame's shape (the
//           old centre crop when u = v = 0.5), up to ZOOM_MAX
//   u, v    the point of the picture in the middle of the frame, as a
//           fraction of its width and height (0.5, 0.5: the middle)
//   ow, oh  the size of the frame the cut part fills (52x64 for ICQ)
//
// The cut part always lies inside the picture: the centre is moved as little
// as needed to keep it there, so the frame never shows anything but the
// picture. The result says where the centre ended up (u, v) and how many
// frame pixels one picture pixel becomes (scale).

'use strict';

/* eslint-disable no-var */
function pictureCrop(w, h, z, u, v, ow, oh) {
  var base = Math.max(ow / w, oh / h);
  var scale = base * z;
  var cw = ow / scale;
  var ch = oh / scale;
  var cx = Math.min(Math.max(u * w, cw / 2), w - cw / 2);
  var cy = Math.min(Math.max(v * h, ch / 2), h - ch / 2);
  // No trailing comma: IE 7 takes it for an error.
  return {
    left: cx - cw / 2, top: cy - ch / 2, width: cw, height: ch,
    scale: scale, u: cx / w, v: cy / h
  };
}
/* eslint-enable no-var */

// The size ICQ 6 re-encodes every buddy icon to before uploading it (see
// shrink-picture.py): the frame the picture is cut to.
const ICON_W = 52;
const ICON_H = 64;
const ZOOM_MAX = 5;

// The zoom and centre from a request, or null when any is missing, not a
// plain decimal number, or out of range. Rounded to four places, which is
// also what the page sends, so equal requests share a rendered file.
function parseCropParams(z, u, v) {
  const num = (s) => (typeof s === 'string' && /^\d{1,2}(\.\d{1,8})?$/.test(s) ? Number(s) : NaN);
  const zoom = num(z);
  const cu = num(u);
  const cv = num(v);
  if (!(zoom >= 1 && zoom <= ZOOM_MAX) || !(cu >= 0 && cu <= 1) || !(cv >= 0 && cv <= 1)) return null;
  const r = (x) => Math.round(x * 10000) / 10000;
  return { z: r(zoom), u: r(cu), v: r(cv) };
}

module.exports = { pictureCrop, parseCropParams, ICON_W, ICON_H, ZOOM_MAX };
