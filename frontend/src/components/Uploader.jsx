import { useState } from 'react';
import { UploadCloud } from 'lucide-react';
import { MAX_UPLOAD_MB } from '../api';

export default function Uploader({ onFile, disabled, selectedName }) {
  const [dragging, setDragging] = useState(false);

  const pick = (file) => {
    if (file && !disabled) onFile(file);
  };

  return (
    <div
      className={`file-uploader ${dragging ? 'dragging' : ''} ${disabled ? 'disabled' : ''}`}
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
      <UploadCloud size={32} className="uploader-icon" aria-hidden="true" />
      <div className="uploader-text" title={selectedName || undefined}>
        {selectedName || 'Select APK target'}
      </div>
      <div className="uploader-subtext">Drag & drop or browse · max {MAX_UPLOAD_MB} MB</div>
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
