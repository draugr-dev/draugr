- **The docs are held to what the renderer prints.** A quoted run carrying a heading or a column
  set Draugr has stopped printing now fails the build, and so does one too wide to be read where it
  is published. Nothing checked that before: the goldens pin the layout and the tracking says which
  documents quote it, and neither could see a document still showing a layout from two releases ago.
