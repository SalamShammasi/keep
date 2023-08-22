import React, { useRef, useState } from "react";
import { getApiURL } from "../../utils/apiUrl";
import { useSession } from "../../utils/customAuth";

const DragAndDrop: React.FC = () => {
  const [isDragActive, setIsDragActive] = useState(false);
  const apiUrl = getApiURL();
  const { data: session } = useSession();
  const [error, setError] = useState<string | null>(null);
  const fileInputRef = useRef(null);


  const onDrop = async (files) => {
    setIsDragActive(false);
    const formData = new FormData();
    formData.append("file", files[0]);

    try {
      const response = await fetch(`${apiUrl}/workflows`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${session?.accessToken}`,
        },
        body: formData,
      });

      if (response.ok) {
        // managed to upload the workflow
        setError(null);
        fileInputRef.current.value = null;
        window.location.reload();
      } else {
        const errorMessage = await response.text();
        setError(errorMessage); // Set the error message
        fileInputRef.current.value = null;
        console.error("Failed to upload file");
      }
    } catch (error) {
      setError("An error occurred during file upload");
      fileInputRef.current.value = null;
      console.error("An error occurred during file upload", error);
    }
  };

  const handleDragEnter = (e) => {
    e.preventDefault();
    setIsDragActive(true);
  };

  const handleDragLeave = (e) => {
    e.preventDefault();
    setIsDragActive(false);
  };

  const handleDragOver = (e) => {
    e.preventDefault();
  };

  return (
    <div
      className={`flex flex-col items-center justify-center h-full w-1/2 mx-auto p-4 border border-gray-300 rounded-lg ${
        isDragActive ? "border-blue-500" : ""
      }`}
      onDragEnter={handleDragEnter}
      onDragLeave={handleDragLeave}
      onDragOver={(e) => {
        e.preventDefault(); // Prevent the default behavior
        handleDragOver(e);
      }}
      onDrop={(e) => {
        e.preventDefault();
        setIsDragActive(false);
        onDrop(e.dataTransfer.files);
      }}
    >
        <>
          <div className="mb-4">
            <svg
              xmlns="http://www.w3.org/2000/svg"
              className="h-12 w-12 text-gray-400"
              viewBox="0 0 20 20"
              fill="currentColor"
            >
              {/* SVG path for the upload icon */}
            </svg>
          </div>
          <p className="mb-2">Drag and drop a workflow here</p>
          <p className="mb-2">or</p>
          <label className="cursor-pointer">
            <span className="text-blue-500">Upload a workflow</span>
            <input
              ref={fileInputRef} // Set the ref for the file input
              type="file"
              className="hidden"
              onChange={(e) => {
                onDrop(e.target.files);
              }}
            />
          </label>
        </>
        {error && <p className="text-red-500 mt-4">Failed to upload the file: {error}<br></br>Please try again with another file.</p>}
    </div>
  );
};

export default DragAndDrop;
