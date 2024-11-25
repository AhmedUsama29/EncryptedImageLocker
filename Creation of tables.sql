
CREATE TABLE Users (
    User_ID INT PRIMARY KEY IDENTITY(1,1), 
    username varchar(30) NOT NULL,         
    FName nvarchar(20),                     
    LName nvarchar(20),                     
    Email VARCHAR(100) UNIQUE NOT NULL,    
    Password varbinary(255) NOT NULL,        
    PhoneNum VARCHAR(20),                  
    Gender varchar(6) CHECK (Gender IN ('Male', 'Female') 
)
CREATE TABLE PasswordEncryption (
    id INT PRIMARY KEY IDENTITY(1,1),      
    user_id INT NOT NULL,                  
    PKey VARCHAR(255) NOT NULL,            
    PIV VARCHAR(255) NOT NULL,             
    CONSTRAINT FK_User_Password FOREIGN KEY (user_id) REFERENCES Users(User_ID) ON DELETE CASCADE
);

CREATE TABLE Images (
    ImgID INT PRIMARY KEY IDENTITY(1,1),  
    Size varchar(20) NOT NULL,                    
    Extension VARCHAR(10) NOT NULL,       
    Name VARCHAR(40) NOT NULL,           
    Category VARCHAR(40),                 
    EncryptedText varbinary(MAX),                   
    User_ID INT NOT NULL,                 
    CONSTRAINT FK_User_Images FOREIGN KEY (User_ID) REFERENCES Users(User_ID) ON DELETE CASCADE
);

CREATE TABLE EncryptionDetails (
    id INT PRIMARY KEY IDENTITY(1,1),     
    imgID INT NOT NULL,                   
    EKey varbinary(255) NOT NULL,           
    iv varbinary(255) NOT NULL,             
    CONSTRAINT FK_Image_Encryption FOREIGN KEY (imgID) REFERENCES Images(ImgID) ON DELETE CASCADE
);
