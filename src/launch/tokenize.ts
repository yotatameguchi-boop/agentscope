/**
 * シェルのコマンド文字列を、実行せずに語へ分割する。
 *
 * - 単一引用符・二重引用符・バックスラッシュを解釈する
 * - ; && || | & 改行 でコマンドを区切る
 * - 変数展開・コマンド置換・グロブ展開はしない（$VAR はそのままの文字列として残す）
 * - 先頭が # の語以降は行末までコメントとして捨てる
 *
 * 完全なシェルの再現ではなく、エージェントの起動フラグを読み取るのに必要な範囲に限る。
 */
export function splitCommands(input: string): string[][] {
  const text = input.replace(/\\\r?\n/g, ' '); // 行継続
  const commands: string[][] = [];
  let words: string[] = [];
  let word = '';
  let inWord = false;
  let i = 0;

  const endWord = () => {
    if (inWord) words.push(word);
    word = '';
    inWord = false;
  };
  const endCommand = () => {
    endWord();
    if (words.length) commands.push(words);
    words = [];
  };

  while (i < text.length) {
    const ch = text[i]!;
    if (ch === "'") {
      const end = text.indexOf("'", i + 1);
      const stop = end === -1 ? text.length : end;
      word += text.slice(i + 1, stop);
      inWord = true;
      i = stop + 1;
      continue;
    }
    if (ch === '"') {
      i++;
      inWord = true;
      while (i < text.length && text[i] !== '"') {
        if (text[i] === '\\' && i + 1 < text.length && '"\\$`'.includes(text[i + 1]!)) {
          word += text[i + 1];
          i += 2;
        } else {
          word += text[i];
          i++;
        }
      }
      i++;
      continue;
    }
    if (ch === '\\' && i + 1 < text.length) {
      word += text[i + 1];
      inWord = true;
      i += 2;
      continue;
    }
    if (ch === '#' && !inWord) {
      const nl = text.indexOf('\n', i);
      i = nl === -1 ? text.length : nl;
      continue;
    }
    if (ch === '\n' || ch === ';') {
      endCommand();
      i++;
      continue;
    }
    if (ch === '&' || ch === '|') {
      endCommand();
      i += text[i + 1] === ch ? 2 : 1;
      continue;
    }
    if (ch === ' ' || ch === '\t' || ch === '\r') {
      endWord();
      i++;
      continue;
    }
    word += ch;
    inWord = true;
    i++;
  }
  endCommand();
  return commands;
}
