// ICQ Revival: tZer thumbnails for the MirandaFinal IEView skin.
//
// A message whose text is exactly "tZer: <name>" gets the tZer's picture
// next to it. The text is read from the page (innerText of the message's
// span.rt-text), never passed to a script: the template calls
// revivalTzers() without arguments. Only names from the table below match;
// the picture's address comes from the table too (images/tzers/*.png in the
// skin folder), so nothing from a message ever becomes part of an address,
// markup or code. Anything else stays plain text.
//
// English names: what ICQ 6.5 sends (en-US TzerLabels.dtd). Russian: its
// ru-RU TzerLabels.dtd, as our tZer menu shows them.

var revivalTzerTable = [
	['gangsta',   "Gangsta'"],
	['canthearu', "Can't Hear U", "Вас не слышно"],
	['skratch',   'Scratch', "Царапина"],
	['boo',       'Booooo'],
	['kisses',    'Kisses', "Поцелуйчики"],
	['chillout',  'Chill Out', "Расслабьтесь"],
	['akitaka',   'Akitaka'],
	['laugh',     'Hilaaarious', "Умооооора"],
	['duh',       'Like Duh!', "Вот дурак!"],
	['beback',    'L8R'],
	['likeu',     'Like U!', "Ты мне нравишься"],
	['sorry',     "I'm Sorry", "Мне очень жаль"]
];

function revivalTrim(s) {
	return s.replace(/^[\s ]+|[\s ]+$/g, '');
}

function revivalTzerFile(name) {
	for (var i = 0; i < revivalTzerTable.length; i++)
		for (var j = 1; j < revivalTzerTable[i].length; j++)
			if (revivalTzerTable[i][j] == name)
				return revivalTzerTable[i][0];
	return null;
}

// Looks at the messages added since the last call (the newest are last).
function revivalTzers() {
	var spans = document.getElementsByTagName('span');
	for (var i = spans.length - 1; i >= 0; i--) {
		var s = spans[i];
		if (s.className != 'rt-text')
			continue;
		if (s.getAttribute('data-rt'))
			break;
		s.setAttribute('data-rt', '1');

		var text = revivalTrim(s.innerText || s.textContent || '');
		if (text.indexOf('tZer:') != 0)
			continue;
		var name = revivalTrim(text.substring(5));
		var file = revivalTzerFile(name);
		if (!file)
			continue;

		var img = document.createElement('img');
		img.className = 'revival-tzer';
		img.src = 'images/tzers/' + file + '.png';
		img.alt = name;
		img.title = name;
		s.parentNode.appendChild(img);
	}
}
