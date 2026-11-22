import { useState } from 'react';
import { FileUp } from 'lucide-react';
import { MAX_UPLOAD_MB } from '../api';

export default function Uploader({ onFile, disabled }) {
  const [dragging, setDragging] = useState(false);

  const pick = (file) => {
    if (file && !disabled) onFile(file);
  };

  return (
    <div
      className={`dropzone ${dragging ? 'is-dragging' : ''} ${disabled ? 'is-disabled' : ''}`}
      onDragOver={(e) => {
        e.preventDefault();
        if (!disabled) setDragging(true);
      }}
      onDragLeave={() => setDragging(false)}
      onDrop={(e) => {
        e.preventDefault();
        setDragging(false);
        pick(e.dataTransfer.files[0]);
      }}
    >
      <FileUp size={28} className="dropzone-icon" aria-hidden="true" />
      <span className="dropzone-title">Drop an APK here, or click to choose one</span>
      <span className="hint">Android packages up to {MAX_UPLOAD_MB} MB</span>
      <input
        type="file"
        accept=".apk,application/vnd.android.package-archive"
        aria-label="Upload APK file"
        disabled={disabled}
        onChange={(e) => {
          pick(e.target.files[0]);
          // Allow re-selecting the same file
          e.target.value = '';
        }}
      />
    </div>
  );
}
